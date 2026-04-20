import Foundation

struct RedirectChainService {
    static func trace(domain: String) async -> ServiceResult<[RedirectHop]> {
        do {
            let hops = try await followChain(startingURL: URL(string: "https://\(domain)")!)
            return hops.isEmpty ? .empty("No redirect data available") : .success(hops)
        } catch {
            do {
                let hops = try await followChain(startingURL: URL(string: "http://\(domain)")!)
                return hops.isEmpty ? .empty("No redirect data available") : .success(hops)
            } catch {
                return .error(error.localizedDescription)
            }
        }
    }

    private static func followChain(startingURL: URL) async throws -> [RedirectHop] {
        let delegate = NoRedirectDelegate()
        let session = URLSession(
            configuration: .ephemeral,
            delegate: delegate,
            delegateQueue: nil
        )
        defer { session.invalidateAndCancel() }

        var hops: [RedirectHop] = []
        var currentURL = startingURL
        let maxRedirects = 10

        for step in 1...maxRedirects + 1 {
            var request = URLRequest(url: currentURL, timeoutInterval: 10)
            request.httpMethod = "GET"

            let (_, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw URLError(.badServerResponse)
            }

            let statusCode = httpResponse.statusCode
            let isRedirect = (300...399).contains(statusCode)

            if isRedirect, let location = httpResponse.value(forHTTPHeaderField: "Location") {
                hops.append(RedirectHop(
                    stepNumber: step,
                    statusCode: statusCode,
                    url: currentURL.absoluteString,
                    isFinal: false
                ))

                // Resolve relative redirects
                if let nextURL = URL(string: location, relativeTo: currentURL)?.absoluteURL {
                    currentURL = nextURL
                } else {
                    break
                }

                if step > maxRedirects { break }
            } else {
                // Non-redirect — this is the final destination
                hops.append(RedirectHop(
                    stepNumber: step,
                    statusCode: statusCode,
                    url: currentURL.absoluteString,
                    isFinal: true
                ))
                break
            }
        }

        return hops
    }
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Don't follow redirects automatically — return nil to stop
        completionHandler(nil)
    }
}
