import axios from "axios"

/**
 * Tests if the API endpoint has proper rate limiting
 * @param {string} url - The API endpoint URL
 * @param {boolean} verbose - Whether to show detailed output
 * @returns {Object} Test result
 */
export async function testRateLimiting(url, verbose = false) {
  const result = {
    test: "rate-limiting",
    vulnerable: false,
    details: "",
    recommendation: "",
  }

  try {
    // Number of requests to send
    const numRequests = 50
    // Time window in milliseconds
    const timeWindow = 5000

    if (verbose) {
      console.log(`Sending ${numRequests} requests in ${timeWindow / 1000} seconds to test rate limiting`)
    }

    const startTime = Date.now()
    let rateLimited = false
    let successfulRequests = 0

    // Send multiple requests in parallel
    const requests = []
    for (let i = 0; i < numRequests; i++) {
      requests.push(
        axios.get(url, {
          validateStatus: (status) => {
            return status < 600 // Accept all status codes
          },
          headers: {
            // Try with different IP headers to test if the API is checking for these
            "X-Forwarded-For": `192.168.1.${i % 255}`,
            "X-Real-IP": `10.0.0.${i % 255}`,
          },
        }),
      )
    }

    // Wait for all requests to complete
    const responses = await Promise.all(requests.map((p) => p.catch((e) => e)))

    // Check responses
    for (const response of responses) {
      if (response instanceof Error) {
        if (verbose) {
          console.log(`Request failed: ${response.message}`)
        }
      } else {
        if (response.status === 429) {
          rateLimited = true
        } else if (response.status >= 200 && response.status < 300) {
          successfulRequests++
        }
      }
    }

    const endTime = Date.now()
    const duration = endTime - startTime

    if (verbose) {
      console.log(`Test completed in ${duration}ms`)
      console.log(`Successful requests: ${successfulRequests}/${numRequests}`)
      console.log(`Rate limited: ${rateLimited}`)
    }

    // Check if rate limiting is implemented
    if (!rateLimited && successfulRequests > numRequests * 0.8) {
      result.vulnerable = true
      result.details = `No rate limiting detected (${successfulRequests}/${numRequests} requests succeeded)`
      result.recommendation = "Implement rate limiting to prevent abuse and DoS attacks"
    }

    // Check for IP spoofing bypass
    if (rateLimited && successfulRequests > numRequests * 0.5) {
      result.vulnerable = true
      result.details = "Rate limiting can be bypassed by spoofing IP addresses"
      result.recommendation =
        "Implement rate limiting based on authenticated user or use a more robust IP detection mechanism"
    }

    return result
  } catch (error) {
    if (verbose) {
      console.error("Error in rate limiting test:", error.message)
    }
    return {
      ...result,
      details: `Error during test: ${error.message}`,
    }
  }
}
