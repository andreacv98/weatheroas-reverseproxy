package main

import (
	"github.com/labstack/echo/v4"
	"log"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	e := echo.New()

	tokenIPInfo := os.Getenv("TOKEN_IPINFO")
	tokenOpenWeather := os.Getenv("TOKEN_OPENWEATHER")

	if tokenIPInfo == "" {
		log.Fatal("No token to ipinfo.io")
	} else if tokenOpenWeather == "" {
		log.Fatal("No token to openweathermap.org")
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

			//may be some extra validations before sending request like Auth etc.
			/*if req.Header.Get("X-Custom-Header") != "123" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
			}*/

			// Update the headers to allow for SSL redirection
			req.Host = urlGeoIP.Host
			req.URL.Host = urlGeoIP.Host
			req.URL.Scheme = urlGeoIP.Scheme
			if clientIp != "::1" {
				req.URL.Path += clientIp
			}
			req.URL.Query().Add("token", tokenIPInfo)

			//trim reverseProxyRoutePrefix
			path := req.URL.Path
			req.URL.Path = strings.TrimLeft(path, reverseProxyRoutePrefix)

			println(req.URL.Path)

			// ServeHttp is non-blocking and uses a go routine under the hood
			proxyGeoIP.ServeHTTP(res, req)
			return nil
		}
	})

	// create the reverse proxyOpenWeather
	urlOpenWeather, err := url.Parse("https://openweathermap.org/")
	if err != nil {
		log.Fatal(err)
	}
	proxyOpenWeather := httputil.NewSingleHostReverseProxy(urlOpenWeather)

	reverseProxyRoutePrefixOW := "/weather"
	routerGroupOW := e.Group(reverseProxyRoutePrefixOW)
	routerGroupOW.Use(func(handlerFunc echo.HandlerFunc) echo.HandlerFunc {
		return func(context echo.Context) error {

			req := context.Request()
			res := context.Response().Writer

			//may be some extra validations before sending request like Auth etc.
			/*if req.Header.Get("X-Custom-Header") != "123" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
			}*/

			// Update the headers to allow for SSL redirection
			req.Host = urlGeoIP.Host
			req.URL.Host = urlGeoIP.Host
			req.URL.Scheme = urlGeoIP.Scheme
			req.URL.Query().Add("appid", tokenOpenWeather)

			//trim reverseProxyRoutePrefix
			path := req.URL.Path
			req.URL.Path = strings.TrimLeft(path, reverseProxyRoutePrefix)

			println(req.URL.Path)

			// ServeHttp is non-blocking and uses a go routine under the hood
			proxyOpenWeather.ServeHTTP(res, req)
			return nil
		}
	})

	errServer := e.Start(":2957")
	if errServer != nil {
		log.Fatal(errServer)
	}
}
