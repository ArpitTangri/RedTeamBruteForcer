1. Multi-Threading: Uses a thread pool (ExecutorService) to run multiple login attempts concurrently, making the process much faster.

2.Rate Limiting: Implements a TokenBucket algorithm to control the number of requests per second. This is crucial for avoiding detection, preventing server overload, and mimicking more realistic attack patterns.

3.Modern HTTP Client: Uses Java's modern HttpClient (from Java 11+) for sending network requests, which is more powerful and flexible than older methods.

4.Response Fingerprinting: It cleverly analyzes the response from the server (status code and body length) to detect a successful login, rather than just looking for a "200 OK." This can bypass simple "invalid password" messages and identify subtle changes that indicate success.

5. Lab/Debug Modes: Includes a "lab mode" that disables SSL certificate verification (useful for test environments) and a "verbose mode" for detailed logging of each attempt.

6.Password Mutations: Can automatically generate variations of passwords from a wordlist (e.g., adding numbers, changing case), increasing the chances of a successful guess.

7.Proxy Support: Allows routing traffic through an HTTP proxy, including support for proxies that require authentication.

8. Comprehensive Logging & Reporting: Saves all results to a brute_results.jsonl file for easy analysis and generates a final human-readable brute_report.txt.
