import axios from "axios"
import chalk from "chalk"

/**
 * Tests if the API endpoint is missing authentication
 * @param {string} url - The API endpoint URL
 * @param {boolean} verbose - Whether to show detailed output
 * @returns {Object} Test result
 */
export async function testMissingAuth(url, verbose = false) {
  const result = {
    test: "missing-auth",
    vulnerable: false,
    details: "",
    recommendation: "",
  }

  try {
    // Skip auth test for public endpoints
    if (url.includes("login") || url.includes("register") || url.includes("public")) {
      if (verbose) {
        console.log(chalk.yellow("Skipping auth test - public endpoint"))
      }
      return result
    }

    // Try to access the endpoint without authentication
    const response = await axios.get(url, {
      validateStatus: (status) => {
        return status < 500 // Accept all status codes less than 500
      },
    })

    if (verbose) {
      console.log(`Response status: ${response.status}`)
      console.log(`Response data:`, response.data)
    }

    // Check if we got a successful response without authentication
    if (response.status === 200 || response.status === 201) {
      // Check if the response contains sensitive data
      const responseStr = JSON.stringify(response.data).toLowerCase()
      const sensitiveDataPatterns = [
        "user",
        "password",
        "email",
        "phone",
        "address",
        "credit",
        "payment",
        "token",
        "key",
        "secret",
        "private",
      ]

      const containsSensitiveData = sensitiveDataPatterns.some((pattern) => responseStr.includes(pattern))

      if (containsSensitiveData) {
        result.vulnerable = true
        result.details = "Endpoint accessible without authentication and returns sensitive data"
        result.recommendation = "Implement proper authentication for this endpoint"
      } else {
        // Even if no sensitive data, it might still be a protected resource
        result.vulnerable = true
        result.details = "Endpoint accessible without authentication"
        result.recommendation = "Verify if this endpoint should require authentication"
      }
    } else if (response.status === 401 || response.status === 403) {
      // This is the expected behavior for protected endpoints
      result.vulnerable = false
    } else {
      // Unexpected response
      result.details = `Unexpected response (${response.status})`
    }

    return result
  } catch (error) {
    if (verbose) {
      console.error("Error in missing auth test:", error.message)
    }
    return {
      ...result,
      details: `Error during test: ${error.message}`,
    }
  }
}
