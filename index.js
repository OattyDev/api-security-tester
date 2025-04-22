#!/usr/bin/env node

import { Command } from "commander"
import chalk from "chalk"
import inquirer from "inquirer"
import ora from "ora"
import { testBruteForce } from "./tests/brute-force.js"
import { testMissingAuth } from "./tests/missing-auth.js"
import { testSqlInjection } from "./tests/sql-injection.js"
import { testRateLimiting } from "./tests/rate-limiting.js"
import { testInfoDisclosure } from "./tests/info-disclosure.js"

const program = new Command()

program.name("api-security-tester").description("CLI tool to test API security vulnerabilities").version("1.0.0")

program
  .command("scan")
  .description("Scan an API endpoint for security vulnerabilities")
  .option("-u, --url <url>", "API base URL to test")
  .option("-e, --endpoints <endpoints>", "Comma-separated list of API endpoints to test")
  .option("-a, --auth <auth>", "Authentication token (if required)")
  .option("-t, --tests <tests>", "Comma-separated list of tests to run (default: all)")
  .option("-v, --verbose", "Show detailed output")
  .action(async (options) => {
    try {
      // If no URL provided, prompt for it
      if (!options.url) {
        const answers = await inquirer.prompt([
          {
            type: "input",
            name: "url",
            message: "Enter the API base URL to test:",
            validate: (input) => (input.length > 0 ? true : "URL is required"),
          },
        ])
        options.url = answers.url
      }

      // If no endpoints provided, prompt for them
      if (!options.endpoints) {
        const answers = await inquirer.prompt([
          {
            type: "input",
            name: "endpoints",
            message: "Enter comma-separated API endpoints to test (e.g., /users,/products):",
            default: "/api",
          },
        ])
        options.endpoints = answers.endpoints
      }

      const endpoints = options.endpoints.split(",").map((e) => e.trim())
      const testsToRun = options.tests ? options.tests.split(",").map((t) => t.trim()) : ["all"]

      console.log(chalk.blue("\n🔒 API Security Tester"))
      console.log(chalk.blue(`Target: ${options.url}`))
      console.log(chalk.blue(`Endpoints: ${endpoints.join(", ")}`))
      console.log(chalk.blue(`Tests: ${testsToRun.join(", ")}\n`))

      const results = {
        vulnerabilities: 0,
        details: [],
      }

      // Run tests
      for (const endpoint of endpoints) {
        const fullUrl = `${options.url}${endpoint}`
        console.log(chalk.yellow(`\nTesting endpoint: ${fullUrl}`))

        if (testsToRun.includes("all") || testsToRun.includes("brute-force")) {
          const spinner = ora("Running brute force test...").start()
          const bruteForceResult = await testBruteForce(fullUrl, options.auth, options.verbose)
          spinner.stop()

          if (bruteForceResult.vulnerable) {
            results.vulnerabilities++
            results.details.push(bruteForceResult)
            console.log(chalk.red(`✗ Vulnerable to brute force attacks: ${bruteForceResult.details}`))
          } else {
            console.log(chalk.green("✓ Not vulnerable to brute force attacks"))
          }
        }

        if (testsToRun.includes("all") || testsToRun.includes("missing-auth")) {
          const spinner = ora("Running missing authentication test...").start()
          const missingAuthResult = await testMissingAuth(fullUrl, options.verbose)
          spinner.stop()

          if (missingAuthResult.vulnerable) {
            results.vulnerabilities++
            results.details.push(missingAuthResult)
            console.log(chalk.red(`✗ Missing authentication: ${missingAuthResult.details}`))
          } else {
            console.log(chalk.green("✓ Authentication is properly implemented"))
          }
        }

        if (testsToRun.includes("all") || testsToRun.includes("sql-injection")) {
          const spinner = ora("Running SQL injection test...").start()
          const sqlInjectionResult = await testSqlInjection(fullUrl, options.verbose)
          spinner.stop()

          if (sqlInjectionResult.vulnerable) {
            results.vulnerabilities++
            results.details.push(sqlInjectionResult)
            console.log(chalk.red(`✗ Vulnerable to SQL injection: ${sqlInjectionResult.details}`))
          } else {
            console.log(chalk.green("✓ Not vulnerable to SQL injection"))
          }
        }

        if (testsToRun.includes("all") || testsToRun.includes("rate-limiting")) {
          const spinner = ora("Running rate limiting bypass test...").start()
          const rateLimitingResult = await testRateLimiting(fullUrl, options.verbose)
          spinner.stop()

          if (rateLimitingResult.vulnerable) {
            results.vulnerabilities++
            results.details.push(rateLimitingResult)
            console.log(chalk.red(`✗ Rate limiting can be bypassed: ${rateLimitingResult.details}`))
          } else {
            console.log(chalk.green("✓ Rate limiting is properly implemented"))
          }
        }

        if (testsToRun.includes("all") || testsToRun.includes("info-disclosure")) {
          const spinner = ora("Running information disclosure test...").start()
          const infoDisclosureResult = await testInfoDisclosure(fullUrl, options.verbose)
          spinner.stop()

          if (infoDisclosureResult.vulnerable) {
            results.vulnerabilities++
            results.details.push(infoDisclosureResult)
            console.log(chalk.red(`✗ Information disclosure detected: ${infoDisclosureResult.details}`))
          } else {
            console.log(chalk.green("✓ No information disclosure detected"))
          }
        }
      }

      // Summary
      console.log(chalk.blue("\n📊 Scan Summary"))
      if (results.vulnerabilities > 0) {
        console.log(chalk.red(`Found ${results.vulnerabilities} vulnerabilities!`))
        console.log(chalk.yellow("Recommendations:"))
        results.details.forEach((vuln) => {
          console.log(chalk.yellow(`- ${vuln.recommendation}`))
        })
      } else {
        console.log(chalk.green("No vulnerabilities found. Good job!"))
      }
    } catch (error) {
      console.error(chalk.red("Error during scan:"), error.message)
      process.exit(1)
    }
  })

program.parse()