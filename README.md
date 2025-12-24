# autotls

autotls is a Go package for generating self-signed TLS certificates. This is useful if your application is behind a load balancer and you want to enable HTTPS between the load balancer and your application.

Satisfies the requirement for end-to-end encryption for your application.

## Usage

```go
package main

import (
	"crypto/tls"
	"log"

	"github.com/yourusername/autotls"
)

func main() {


	cert, err := autotls.GenerateSelfSignedCert(
        "localhost", // common name
        []string{"127.0.0.1", "::1"}, // ip addresses
    )
	if err != nil {
		log.Fatal(err)
	}

    httpServer := &http.Server{
		Addr:              ":8443",
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
		TLSConfig:         &tls.Config{
		Certificates: []tls.Certificate{cert},
	},
	}

	log.Println("Server started on :8443")
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
```

## License

autotls is licensed under the [Apache 2 License](LICENSE).