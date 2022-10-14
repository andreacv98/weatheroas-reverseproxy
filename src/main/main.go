package main

import (
	"errors"
	"github.com/labstack/echo/v4"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	e := echo.New()

	globalAuthZToken := os.Getenv("TOKEN_GLOBALAUTHZ")
	tokenIPInfo := os.Getenv("TOKEN_IPINFO")

	if globalAuthZToken == "" {
		log.Fatal("No default authz token found")
	} else if tokenIPInfo == "" {
		log.Fatal("No token to ipinfo.io")
	}

	// create the reverse proxyGeoIP
	urlGeoIP, err := url.Parse("https://ipinfo.io")
	if err != nil {
		log.Fatal(err)
	}
	proxyGeoIP := httputil.NewSingleHostReverseProxy(urlGeoIP)

	reverseProxyRoutePrefix := "/geoip"
	routerGroup := e.Group(reverseProxyRoutePrefix)
	routerGroup.Use(func(handlerFunc echo.HandlerFunc) echo.HandlerFunc {
		return func(context echo.Context) error {

			req := context.Request()
			res := context.Response().Writer
			clientIp := context.RealIP()

			// AuthZ check
			if req.Header.Get("Authorization") != globalAuthZToken {
				return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid authorization token")
			}

			// Update the headers to allow for SSL redirection
			req.Host = urlGeoIP.Host
			req.URL.Host = urlGeoIP.Host
			req.URL.Scheme = urlGeoIP.Scheme
			isPrivateIP, errPrivateIP := privateIP(clientIp)
			if errPrivateIP != nil {
				log.Panic(errPrivateIP)
			} else if !isPrivateIP {
				req.URL.Path += clientIp
			}
			// delete authz token to proxy server
			req.Header.Del("Authorization")
			// add token to real third-party server
			req.URL.Query().Add("token", tokenIPInfo)

			//trim reverseProxyRoutePrefix
			path := req.URL.Path
			req.URL.Path = strings.TrimLeft(path, reverseProxyRoutePrefix)

			log.Print("New request from " + context.RealIP() + " to " + req.URL.String())

			// ServeHttp is non-blocking and uses a go routine under the hood
			proxyGeoIP.ServeHTTP(res, req)
			return nil
		}
	})

	// create the reverse proxyOpenMeteo
	urlOpenMeteo, err := url.Parse("https://api.open-meteo.com/v1/forecast")
	if err != nil {
		log.Fatal(err)
	}
	proxyOpenMeteo := httputil.NewSingleHostReverseProxy(urlOpenMeteo)

	reverseProxyRoutePrefixOM := "/weather"
	routerGroupOM := e.Group(reverseProxyRoutePrefixOM)
	routerGroupOM.Use(func(handlerFunc echo.HandlerFunc) echo.HandlerFunc {
		return func(context echo.Context) error {

			req := context.Request()
			res := context.Response().Writer

			// AuthZ check
			if req.Header.Get("Authorization") != globalAuthZToken {
				return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid authorization token")
			}

			// Update the headers to allow for SSL redirection
			req.Host = urlOpenMeteo.Host
			req.URL.Host = urlOpenMeteo.Host
			req.URL.Scheme = urlOpenMeteo.Scheme
			// delete authz token to proxy server
			req.Header.Del("Authorization")

			//trim reverseProxyRoutePrefix
			path := req.URL.Path
			req.URL.Path = strings.TrimLeft(path, reverseProxyRoutePrefixOM)

			log.Print("New request from " + context.RealIP() + " to " + req.URL.String())

			// ServeHttp is non-blocking and uses a go routine under the hood
			proxyOpenMeteo.ServeHTTP(res, req)
			return nil
		}
	})

	errServer := e.Start(":2957")
	if errServer != nil {
		log.Fatal(errServer)
	}
}

func privateIP(ip string) (bool, error) {
	var err error
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		err = errors.New("invalid IP")
	} else {
		_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
		_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
		_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
		_, localhost127, _ := net.ParseCIDR("127.0.0.1/8")
		_, localhostIPv6, _ := net.ParseCIDR("::1/1")
		private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP) || localhost127.Contains(IP) || localhostIPv6.Contains(IP)
	}
	return private, err
}
