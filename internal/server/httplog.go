package server

/*
 * Copyright (c) 2015 99designs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

import (
	"log"
	"net/http"
	"time"
)

type loggingMiddlewareResponseWriter struct {
	http.ResponseWriter
	Code int
}

func (w *loggingMiddlewareResponseWriter) WriteHeader(statusCode int) {
	w.Code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func withLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestStart := time.Now()
		w2 := &loggingMiddlewareResponseWriter{w, http.StatusOK}
		handler.ServeHTTP(w2, r)
		log.Printf("http: %s: %d %s %s (%s)", r.RemoteAddr, w2.Code, r.Method, r.URL, time.Since(requestStart))
	})
}
