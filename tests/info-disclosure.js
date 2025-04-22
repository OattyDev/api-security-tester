import axios from "axios"

/**
 * Tests if the API endpoint discloses sensitive information
 * @param {string} url - The API endpoint URL
 * @param {boolean} verbose - Whether to show detailed output
 * @returns {Object} Test result
 */
export async function testInfoDisclosure(url, verbose = false) {
  const result = {
    test: "info-disclosure",
    vulnerable: false,
    details: "",
    recommendation: "",
  }

  try {
    // Check for common information disclosure in headers and error messages
    const response = await axios.get(url, {
      validateStatus: (status) => {
        return status < 600 // Accept all status codes
      },
    })

    if (verbose) {
      console.log("Response headers:", response.headers)
      console.log("Response status:", response.status)
    }

    // Check headers for sensitive information
    const sensitiveHeaders = []
    const headersToCheck = [
      "server",
      "x-powered-by",
      "x-aspnet-version",
      "x-aspnetmvc-version",
      "x-runtime",
      "x-version",
      "x-generator",
      "x-drupal-cache",
      "x-drupal-dynamic-cache",
      "x-wordpress-cache",
    ]

    for (const header of headersToCheck) {
      if (response.headers[header]) {
        sensitiveHeaders.push(`${header}: ${response.headers[header]}`)
      }
    }

    // Check for detailed error messages
    let detailedError = false
    let errorDetails = ""

    if (response.status >= 400 && response.status < 600) {
      const responseStr = JSON.stringify(response.data).toLowerCase()
      const errorPatterns = [
        "stack trace",
        "exception",
        "traceback",
        "at line",
        "syntax error",
        "unexpected token",
        "undefined variable",
        "cannot read property",
        "null reference",
        "file path",
        "directory path",
        "database error",
      ]

      for (const pattern of errorPatterns) {
        if (responseStr.includes(pattern)) {
          detailedError = true
          errorDetails = `Error response contains "${pattern}"`
          break
        }
      }
    }

    // Check for sensitive data in response
    let sensitiveData = false
    let sensitiveDataDetails = ""

    const responseStr = JSON.stringify(response.data).toLowerCase()
    const sensitiveDataPatterns = [
      "password",
      "secret",
      "token",
      "key",
      "private",
      "credential",
      "api_key",
      "apikey",
      "auth",
      "jwt",
      "ssh",
      "ssl",
      "cert",
    ]

    for (const pattern of sensitiveDataPatterns) {
      if (responseStr.includes(pattern)) {
        sensitiveData = true
        sensitiveDataDetails = `Response contains "${pattern}"`
        break
      }
    }

    // Check for common debug endpoints
    const debugEndpoints = [
      "/debug",
      "/status",
      "/health",
      "/metrics",
      "/admin",
      "/actuator",
      "/swagger",
      "/api-docs",
      "/openapi.json",
      "/trace",
      "/env",
    ]

    let debugEndpointVulnerable = false
    let debugEndpointDetails = ""

    for (const endpoint of debugEndpoints) {
      try {
        const debugUrl = new URL(endpoint, url).toString()
        const debugResponse = await axios.get(debugUrl, {
          validateStatus: (status) => {
            return status < 600 // Accept all status codes
          },
          timeout: 2000, // Short timeout for these requests
        })

        if (debugResponse.status === 200) {
          debugEndpointVulnerable = true
          debugEndpointDetails = `Debug endpoint accessible: ${endpoint}`
          break
        }
      } catch (error) {
        // Ignore errors for debug endpoints
      }
    }

    // Determine if vulnerable
    if (sensitiveHeaders.length > 0 || detailedError || sensitiveData || debugEndpointVulnerable) {
      result.vulnerable = true

      const details = []
      if (sensitiveHeaders.length > 0) {
        details.push(`Sensitive headers: ${sensitiveHeaders.join(", ")}`)
      }
      if (detailedError) {
        details.push(errorDetails)
      }
      if (sensitiveData) {
        details.push(sensitiveDataDetails)
      }
      if (debugEndpointVulnerable) {
        details.push(debugEndpointDetails)
      }

      result.details = details.join("; ")
      result.recommendation =
        "Remove version information from headers, disable detailed error messages in production, and secure or disable debug endpoints"
    }

    return result
  } catch (error) {
    if (verbose) {
      console.error("Error in information disclosure test:", error.message)
    }
    return {
      ...result,
      details: `Error during test: ${error.message}`,
    }
  }
}
