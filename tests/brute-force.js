import axios from "axios"
import chalk from "chalk"

/**
 * Tests if the API endpoint is vulnerable to brute force attacks
 * @param {string} url - The API endpoint URL
 * @param {string} authToken - Optional authentication token
 * @param {boolean} verbose - Whether to show detailed output
 * @returns {Object} Test result
 */
export async function testBruteForce(url, authToken, verbose = false) {
  const result = {
    test: "brute-force",
    vulnerable: false,
    details: "",
    recommendation: "",
  }

  try {
    // Common username/password combinations to try
    const credentials = [
      { username: "admin", password: "admin" },
      { username: "admin", password: "password" },
      { username: "user", password: "password" },
      { username: "test", password: "test" },
      { username: "guest", password: "guest" },
    ]

    // Determine if the endpoint is a login endpoint
    const isLoginEndpoint = url.includes("login") || url.includes("auth") || url.includes("signin")

    if (!isLoginEndpoint) {
      if (verbose) {
        console.log(chalk.yellow("Skipping brute force test - not a login endpoint"))
      }
      return result
    }

    let successfulLogin = false
    let successfulCredentials = null

    // Try each credential pair
    for (const cred of credentials) {
      if (verbose) {
        console.log(`Trying credentials: ${cred.username}/${cred.password}`)
      }

      try {
        const response = await axios.post(
          url,
          {
            username: cred.username,
            password: cred.password,
          },
          {
            headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
          },
        )

        // Check if login was successful (usually indicated by a token or success message)
        if (
          response.status === 200 &&
          (response.data.token || response.data.access_token || response.data.success === true)
        ) {
          successfulLogin = true
          successfulCredentials = cred
          break
        }
      } catch (error) {
        // Expected for failed login attempts
        if (verbose) {
          console.log(`Login failed with ${cred.username}/${cred.password}`)
        }
      }
    }

    // Check if we were able to brute force
    if (successfulLogin) {
      result.vulnerable = true
      result.details = `Successfully logged in with ${successfulCredentials.username}/${successfulCredentials.password}`
      result.recommendation =
        "Implement account lockout after multiple failed attempts, use CAPTCHA, and enforce strong password policies"
    } else {
      // Check if there's rate limiting
      let rateLimited = false
      for (let i = 0; i < 20; i++) {
        try {
          await axios.post(url, {
            username: "admin",
            password: "wrong" + i,
          })
        } catch (error) {
          if (error.response && error.response.status === 429) {
            rateLimited = true
            break
          }
        }
      }

      if (!rateLimited) {
        result.vulnerable = true
        result.details = "No rate limiting detected for multiple failed login attempts"
        result.recommendation = "Implement rate limiting to prevent brute force attacks"
      }
    }

    return result
  } catch (error) {
    if (verbose) {
      console.error("Error in brute force test:", error.message)
    }
    return {
      ...result,
      details: `Error during test: ${error.message}`,
    }
  }
}