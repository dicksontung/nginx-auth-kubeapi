/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"io/ioutil"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	authv1 "k8s.io/api/authentication/v1"
)

var (
	bearerPrefix = "Bearer "
	bearerLen    = len(bearerPrefix)

	kubeApiAddr             = "https://kubernetes.default.svc"
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountToken     = ""
	port                    = 80
	client                  = cleanhttp.DefaultPooledClient()
	caCertPath              = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the token review auth server",
	Long:  `Starts the token review auth server`,
	Run: func(cmd *cobra.Command, args []string) {
		setupTicker()
		setupCaCert()
		http.HandleFunc("/", httpHandleGetRoot)
		http.HandleFunc("/events", httpHandleGetRoot)
		http.HandleFunc("/healthz", httpHandleGetHealthz)
		fmt.Printf("Listening on port :%v", port)
		err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v", err)
		}
	},
}

func setupTicker() {
	ticker := time.NewTicker(300 * time.Second)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				readToken()
			}
		}
	}()
}

func setupCaCert() {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("unable to read cacert: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}
	client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
}

func readToken() {
	b, err := ioutil.ReadFile(serviceAccountTokenPath)
	if err != nil {
		log.Fatalf("unable to read serviceAccountToken from path: %v", err)
	}
	serviceAccountToken = string(b)
}

func httpHandleGetHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	resp := make(map[string]string)
	resp["message"] = "Status OK"
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
	return
}

func getBearer(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	if len(authz) < bearerLen {
		return "", fmt.Errorf("authorization too short: %v", len(authz))
	}
	if authz[:bearerLen] != bearerPrefix {
		return "", fmt.Errorf("no bearer token: %v", bearerPrefix)
	}
	return authz[bearerLen:], nil
}

func handleHttpError(code int, err error, w http.ResponseWriter, r *http.Request) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	logger.Error("unable to read payload from request",
		zap.Error(err),
	)
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	resp := make(map[string]string)
	resp["error"] = fmt.Sprintf("%v", err)
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}

func httpHandleGetRoot(w http.ResponseWriter, r *http.Request) {
	token, err := getBearer(r)
	if err != nil {
		handleHttpError(http.StatusUnauthorized, err, w, r)
		return
	}
	trReq := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}
	trJSON, err := json.Marshal(trReq)
	if err != nil {
		handleHttpError(500, err, w, r)
		return
	}

	// Build the request to the serviceAccountToken review API
	url := fmt.Sprintf("%s/apis/authentication.k8s.io/v1/tokenreviews", strings.TrimSuffix(kubeApiAddr, "/"))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(trJSON))
	if err != nil {
		handleHttpError(500, err, w, r)
		return
	}
	// If we have a configured TokenReviewer JWT use it as the bearer, otherwise
	// try to use the passed in JWT.
	if len(serviceAccountToken) < 1 {
		readToken()
	}
	bearer := fmt.Sprintf("Bearer %s", serviceAccountToken)
	bearer = strings.TrimSpace(bearer)

	// Set the JWT as the Bearer serviceAccountToken
	req.Header.Set("Authorization", bearer)

	// Set the MIME type headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		handleHttpError(500, err, w, r)
		return
	}

	// Parse the resp into a tokenreview object or a kubernetes error type
	response, err := parseResponse(resp)
	switch {
	case kubeerrors.IsUnauthorized(err):
		// If the err is unauthorized that means the serviceAccountToken has since been deleted;
		// this can happen if the service account is deleted, and even if it has
		// since been recreated the serviceAccountToken will have changed, which means our
		// caller will need to be updated accordingly.
		handleHttpError(401, errors.New("lookup failed: service account unauthorized; this could mean it has been deleted or recreated with a new serviceAccountToken"), w, r)
		return
	case err != nil:
		handleHttpError(500, err, w, r)
	}

	if response.Status.Error != "" {
		handleHttpError(500, fmt.Errorf("lookup failed: %s", response.Status.Error), w, r)
		return
	}

	if !response.Status.Authenticated {
		handleHttpError(401, errors.New("lookup failed: service account jwt not valid"), w, r)
		return
	}
	query := r.URL.Query()["group"]
	if len(query) > 0 {
		usergroup := map[string]bool{}
		for _, group := range response.Status.User.Groups {
			usergroup[group] = true
		}
		authenticated := false
		for _, value := range query {
			if usergroup[value] {
				authenticated = true
				break
			}
		}
		if !authenticated {
			handleHttpError(401, fmt.Errorf("user not in group: %v", query), w, r)
			return
		}
	}
	body, err := json.Marshal(response.Status)
	if err != nil {
		handleHttpError(500, err, w, r)
		return
	}
	log.Printf("ok: %v", response.Status)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	// The username is of format: system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)
	//parts := strings.Split(response.Status.User.Username, ":")
	//if len(parts) != 4 {
	//	handleHttpError(401, )
	//	return nil, errors.New("lookup failed: unexpected username format")
	//}
	//
	//// Validate the user that comes back from serviceAccountToken review is a service account
	//if parts[0] != "system" || parts[1] != "serviceaccount" {
	//	return nil, errors.New("lookup failed: username returned is not a service account")
	//}

}

func parseResponse(resp *http.Response) (*authv1.TokenReview, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// If the request was not a success create a kuberenets error
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent {
		return nil, kubeerrors.NewGenericServerResponse(resp.StatusCode, "POST", schema.GroupResource{}, "", strings.TrimSpace(string(body)), 0, true)
	}

	// If we can successfully Unmarshal into a status object that means there is
	// an error to return
	errStatus := &metav1.Status{}
	err = json.Unmarshal(body, errStatus)
	if err == nil && errStatus.Status != metav1.StatusSuccess {
		return nil, kubeerrors.FromObject(runtime.Object(errStatus))
	}

	// Unmarshal the resp body into a TokenReview Object
	trResp := &authv1.TokenReview{}
	err = json.Unmarshal(body, trResp)
	if err != nil {
		return nil, err
	}

	return trResp, nil
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().IntVarP(&port, "port", "", viper.GetInt("NGINX_AUTH_PORT"), "port number to listen on defaults to `80`")
	startCmd.Flags().StringVarP(&kubeApiAddr, "kube-api-addr", "", viper.GetString("NGINX_AUTH_KUBE_API_ADDR"), "kube-api address defaults to `https://kubernetes.default.svc`")
	startCmd.Flags().StringVarP(&serviceAccountTokenPath, "service-account-token-path", "", viper.GetString("NGINX_AUTH_SERVICE_ACCOUNT_TOKEN_PATH"), "service account token path defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`")
	startCmd.Flags().StringVarP(&caCertPath, "ca-cert-path", "", viper.GetString("NGINX_AUTH_CA_CERT_PATH"), "ca cert path defaults to `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
