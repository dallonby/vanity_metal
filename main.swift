import Foundation
import Metal
import Security
import ArgumentParser

struct VanityGenerator: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "vanity_metal",
        abstract: "GPU-accelerated vanity Ethereum address generator for Apple Silicon (Profanity-killer edition)"
    )

    @Option(name: .shortAndLong, help: "Number of addresses to generate")
    var count: Int = 10

    @Option(name: .shortAndLong, help: "Address prefix to match (without 0x)")
    var prefix: String = "badbad"

    @Option(name: .shortAndLong, help: "Iterations per batch (more = less overhead)")
    var iterations: Int = 2000  // Balanced - more iterations can cause hangs

    @Option(name: .shortAndLong, help: "Number of GPU threads")
    var threads: Int = 1048576  // 1M threads - best throughput

    @Option(name: .shortAndLong, help: "Inverse batch size (32 optimal for Metal)")
    var batchSize: Int = 32

    func run() throws {
        print("Vanity Address Generator (Metal/Apple Silicon) - Profanity-killer Edition")
        print("Finding \(count) addresses with prefix 0x\(prefix)")
        print("---")

        guard let device = MTLCreateSystemDefaultDevice() else {
            print("Error: Metal is not supported on this device")
            throw ExitCode.failure
        }

        print("Using GPU: \(device.name)")

        // Load the shader
        let library: MTLLibrary
        do {
            if FileManager.default.fileExists(atPath: "./shader.metallib") {
                library = try device.makeLibrary(filepath: "./shader.metallib")
            } else {
                let sourceCode = try String(contentsOfFile: "./shader.metal", encoding: .utf8)
                library = try device.makeLibrary(source: sourceCode, options: nil)
            }
        } catch {
            print("Error loading shader: \(error)")
            throw ExitCode.failure
        }

        // Get kernels
        guard let initKernel = library.makeFunction(name: "compute_initial_points"),
              let inverseKernel = library.makeFunction(name: "profanity_inverse_batch"),
              let iterateKernel = library.makeFunction(name: "profanity_iterate") else {
            print("Error: Could not find kernel functions")
            throw ExitCode.failure
        }

        let initPipeline = try device.makeComputePipelineState(function: initKernel)
        let inversePipeline = try device.makeComputePipelineState(function: inverseKernel)
        let iteratePipeline = try device.makeComputePipelineState(function: iterateKernel)

        guard let commandQueue = device.makeCommandQueue() else {
            print("Error: Could not create command queue")
            throw ExitCode.failure
        }

        // Thread configuration - must be divisible by batchSize
        let totalThreads = (threads / batchSize) * batchSize
        let inverseThreads = totalThreads / batchSize
        let maxThreadsPerGroup = iteratePipeline.maxTotalThreadsPerThreadgroup
        let threadGroupSize = MTLSize(width: min(256, maxThreadsPerGroup), height: 1, depth: 1)

        print("Using \(totalThreads) GPU threads, batch size \(batchSize)")
        print("Architecture: Batch inversion + lambda chaining (profanity2-style)")
        print("")

        // Allocate buffers (32-bit limbs, 8 words per number)
        let wordsPerNumber = 8
        let bytesPerNumber = wordsPerNumber * MemoryLayout<UInt32>.size

        // Private keys: 8 x uint32 per thread
        guard let privateKeysBuffer = device.makeBuffer(length: totalThreads * bytesPerNumber, options: .storageModeShared) else {
            print("Error: Could not allocate private keys buffer")
            throw ExitCode.failure
        }

        // DeltaX: 8 x uint32 per thread
        guard let deltaXBuffer = device.makeBuffer(length: totalThreads * bytesPerNumber, options: .storageModeShared) else {
            print("Error: Could not allocate deltaX buffer")
            throw ExitCode.failure
        }

        // Previous lambda: 8 x uint32 per thread
        guard let prevLambdaBuffer = device.makeBuffer(length: totalThreads * bytesPerNumber, options: .storageModeShared) else {
            print("Error: Could not allocate prevLambda buffer")
            throw ExitCode.failure
        }

        // Inverses buffer: 8 x uint32 per thread
        guard let inversesBuffer = device.makeBuffer(length: totalThreads * bytesPerNumber, options: .storageModeShared) else {
            print("Error: Could not allocate inverses buffer")
            throw ExitCode.failure
        }

        // Results buffer (thread ID + iteration pairs)
        let maxResults = count * 10  // Allow for some buffer
        guard let resultsBuffer = device.makeBuffer(length: maxResults * 2 * MemoryLayout<UInt32>.size, options: .storageModeShared) else {
            print("Error: Could not allocate results buffer")
            throw ExitCode.failure
        }

        // Found count buffer
        guard let foundCountBuffer = device.makeBuffer(length: MemoryLayout<UInt32>.size, options: .storageModeShared) else {
            print("Error: Could not allocate found count buffer")
            throw ExitCode.failure
        }
        foundCountBuffer.contents().bindMemory(to: UInt32.self, capacity: 1).pointee = 0

        // Iteration counter buffer (one per thread)
        guard let iterCounterBuffer = device.makeBuffer(length: totalThreads * MemoryLayout<UInt32>.size, options: .storageModeShared) else {
            print("Error: Could not allocate iteration counter buffer")
            throw ExitCode.failure
        }

        // Prefix buffer
        let prefixBytes = hexStringToBytes(prefix)
        let prefixLen = UInt32(prefix.count)
        guard let prefixBuffer = device.makeBuffer(bytes: prefixBytes, length: max(prefixBytes.count, 1), options: .storageModeShared) else {
            print("Error: Could not allocate prefix buffer")
            throw ExitCode.failure
        }

        // Debug buffer: 24 x uint32 (8 for x, 8 for y, 8 for hash)
        guard let debugBuffer = device.makeBuffer(length: 24 * MemoryLayout<UInt32>.size, options: .storageModeShared) else {
            print("Error: Could not allocate debug buffer")
            throw ExitCode.failure
        }
        memset(debugBuffer.contents(), 0, 24 * MemoryLayout<UInt32>.size)

        var prefixLenVal = prefixLen
        var maxResultsVal = UInt32(maxResults)
        var batchSizeVal = UInt32(batchSize)

        let startTime = Date()
        var totalKeysChecked: UInt64 = 0
        var foundResults = 0
        var batchCount = 0

        // Store original private keys for result recovery
        var storedPrivateKeys: [[UInt32]] = []

        // Main loop
        while foundResults < count {
            batchCount += 1

            // Step 1: Generate cryptographically secure random private keys
            let keysPtr = privateKeysBuffer.contents()
            let keysByteCount = totalThreads * bytesPerNumber
            let status = SecRandomCopyBytes(kSecRandomDefault, keysByteCount, keysPtr)
            guard status == errSecSuccess else {
                print("\nError: Failed to generate secure random bytes (status: \(status))")
                throw ExitCode.failure
            }

            // DEBUG: Set first thread's key to a known value for testing
            if batchCount == 1 {
                let testKeyPtr = keysPtr.bindMemory(to: UInt32.self, capacity: wordsPerNumber)
                // Set key to 2 (little-endian: d[0]=2, rest=0)
                // k=1 hits edge case where k*G = G, and G+G needs doubling not addition
                testKeyPtr[0] = 2
                for i in 1..<wordsPerNumber { testKeyPtr[i] = 0 }
                print("DEBUG: Thread 0 key set to 2 for testing")
            }

            // Store private keys for later recovery
            let keysTypedPtr = keysPtr.bindMemory(to: UInt32.self, capacity: totalThreads * wordsPerNumber)
            storedPrivateKeys = []
            for t in 0..<totalThreads {
                var key = [UInt32](repeating: 0, count: wordsPerNumber)
                for w in 0..<wordsPerNumber {
                    key[w] = keysTypedPtr[t * wordsPerNumber + w]
                }
                storedPrivateKeys.append(key)
            }

            // Reset iteration counters
            memset(iterCounterBuffer.contents(), 0, totalThreads * MemoryLayout<UInt32>.size)

            // Step 2: Compute initial points (slow, once per batch)
            if let commandBuffer = commandQueue.makeCommandBuffer(),
               let encoder = commandBuffer.makeComputeCommandEncoder() {

                encoder.setComputePipelineState(initPipeline)
                encoder.setBuffer(privateKeysBuffer, offset: 0, index: 0)
                encoder.setBuffer(deltaXBuffer, offset: 0, index: 1)
                encoder.setBuffer(prevLambdaBuffer, offset: 0, index: 2)

                let gridSize = MTLSize(width: totalThreads, height: 1, depth: 1)
                encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
                encoder.endEncoding()

                commandBuffer.commit()
                commandBuffer.waitUntilCompleted()
            }

            // DEBUG: After init, dump thread 0's deltaX to verify scalar mult
            if batchCount == 1 {
                let deltaPtr = deltaXBuffer.contents().bindMemory(to: UInt32.self, capacity: wordsPerNumber)
                var deltaHex = "0x"
                for j in stride(from: 7, through: 0, by: -1) {
                    deltaHex += String(format: "%08x", deltaPtr[j])
                }
                print("DEBUG: Thread 0 deltaX after init: \(deltaHex)")
                print("DEBUG: For key=2: k*G = 2G, then init adds G to get 3G")
                print("DEBUG: Expected deltaX = 3G.x - G.x")
                // 3*G.x = 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
                // G.x   = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
                // Expected delta = 3G.x - G.x = 0x7f7243828f7b8563f3940df02f163b22b23529ca560f6ce92c0f6fb8a5e81f61
            }

            // Step 3: Run iterations with batch inversion
            // Use single encoder, alternate between inverse and iterate kernels
            if let commandBuffer = commandQueue.makeCommandBuffer(),
               let encoder = commandBuffer.makeComputeCommandEncoder() {

                let inverseGridSize = MTLSize(width: inverseThreads, height: 1, depth: 1)
                let iterateGridSize = MTLSize(width: totalThreads, height: 1, depth: 1)

                for _ in 0..<iterations {
                    // Inverse kernel
                    encoder.setComputePipelineState(inversePipeline)
                    encoder.setBuffer(deltaXBuffer, offset: 0, index: 0)
                    encoder.setBuffer(inversesBuffer, offset: 0, index: 1)
                    encoder.setBytes(&batchSizeVal, length: MemoryLayout<UInt32>.size, index: 2)
                    encoder.dispatchThreads(inverseGridSize, threadsPerThreadgroup: threadGroupSize)

                    // Iterate kernel
                    encoder.setComputePipelineState(iteratePipeline)
                    encoder.setBuffer(deltaXBuffer, offset: 0, index: 0)
                    encoder.setBuffer(prevLambdaBuffer, offset: 0, index: 1)
                    encoder.setBuffer(inversesBuffer, offset: 0, index: 2)
                    encoder.setBuffer(resultsBuffer, offset: 0, index: 3)
                    encoder.setBuffer(foundCountBuffer, offset: 0, index: 4)
                    encoder.setBuffer(prefixBuffer, offset: 0, index: 5)
                    encoder.setBytes(&prefixLenVal, length: MemoryLayout<UInt32>.size, index: 6)
                    encoder.setBytes(&maxResultsVal, length: MemoryLayout<UInt32>.size, index: 7)
                    encoder.setBuffer(iterCounterBuffer, offset: 0, index: 8)
                    encoder.setBuffer(debugBuffer, offset: 0, index: 9)
                    encoder.dispatchThreads(iterateGridSize, threadsPerThreadgroup: threadGroupSize)
                }

                encoder.endEncoding()
                commandBuffer.commit()
                commandBuffer.waitUntilCompleted()
            }

            totalKeysChecked += UInt64(totalThreads) * UInt64(iterations)
            let newFoundCount = Int(foundCountBuffer.contents().bindMemory(to: UInt32.self, capacity: 1).pointee)

            // Check for new results
            if newFoundCount > foundResults {
                let resultsPtr = resultsBuffer.contents().bindMemory(to: UInt32.self, capacity: maxResults * 2)
                let debugPtr = debugBuffer.contents().bindMemory(to: UInt32.self, capacity: 24)

                for i in foundResults..<min(newFoundCount, count) {
                    let threadId = Int(resultsPtr[i * 2])
                    let iteration = Int(resultsPtr[i * 2 + 1])

                    // Recover private key: original key + iteration offset
                    if threadId < storedPrivateKeys.count {
                        var privateKey = storedPrivateKeys[threadId]
                        // The iteration tells us which point was checked
                        // After init: state is for (k+1)*G
                        // iter=n means we advanced n times and checked (k+n+1)*G
                        // So the private key is k + n + 1
                        let baseKey = formatKeyAsHex(privateKey)
                        addToKey(&privateKey, UInt64(iteration + 1))
                        let hexKey = formatKeyAsHex(privateKey)
                        print("\nFound #\(i + 1): iter=\(iteration), baseKey=\(baseKey), finalKey=\(hexKey)")

                        // Print debug info for first match
                        if i == 0 {
                            // Extract x (big-endian hex)
                            var xHex = "0x"
                            for j in stride(from: 7, through: 0, by: -1) {
                                xHex += String(format: "%08x", debugPtr[j])
                            }
                            // Extract y (big-endian hex)
                            var yHex = "0x"
                            for j in stride(from: 15, through: 8, by: -1) {
                                yHex += String(format: "%08x", debugPtr[j])
                            }
                            // Extract hash (little-endian bytes -> hex)
                            var hashHex = "0x"
                            for j in 0..<8 {
                                hashHex += String(format: "%08x", debugPtr[16 + j].byteSwapped)
                            }
                            print("  DEBUG pubkey x: \(xHex)")
                            print("  DEBUG pubkey y: \(yHex)")
                            print("  DEBUG hash:     \(hashHex)")
                            print("  DEBUG address:  0x\(String(hashHex.dropFirst(26)))")

                            // Verify: compute pubkey || cast keccak
                            print("  VERIFY: Run these commands:")
                            print("    cast keccak \"0x\(String(xHex.dropFirst(2)))\(String(yHex.dropFirst(2)))\"")
                            print("    cast wallet address --private-key \(hexKey)")
                        }
                    }
                }

                foundResults = min(newFoundCount, count)
            }

            // Print progress
            let elapsed = Date().timeIntervalSince(startTime)
            let rate = Double(totalKeysChecked) / elapsed
            print("\rBatch \(batchCount): \(foundResults)/\(count) found, \(String(format: "%.2f", rate / 1_000_000))M keys/sec, \(String(format: "%.1f", elapsed))s elapsed", terminator: "")
            fflush(stdout)
        }

        print("\n---")
        let elapsed = Date().timeIntervalSince(startTime)
        print(String(format: "Generated %d addresses in %.2fs (%.2fM keys/sec average)",
                     count, elapsed, Double(totalKeysChecked) / elapsed / 1_000_000))
    }

    func hexStringToBytes(_ hex: String) -> [UInt8] {
        var bytes = [UInt8]()
        var paddedHex = hex
        if paddedHex.count % 2 != 0 {
            paddedHex = paddedHex + "0"
        }

        var index = paddedHex.startIndex
        while index < paddedHex.endIndex {
            let nextIndex = paddedHex.index(index, offsetBy: 2)
            let byteString = String(paddedHex[index..<nextIndex])
            if let byte = UInt8(byteString, radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }

    func addToKey(_ key: inout [UInt32], _ value: UInt64) {
        // Add value to little-endian 256-bit number
        var carry = value
        for i in 0..<key.count {
            let sum = UInt64(key[i]) + (carry & 0xFFFFFFFF)
            key[i] = UInt32(sum & 0xFFFFFFFF)
            carry = (carry >> 32) + (sum >> 32)
            if carry == 0 { break }
        }
    }

    func formatKeyAsHex(_ key: [UInt32]) -> String {
        // Format as big-endian hex (most significant first)
        var hex = "0x"
        for i in stride(from: key.count - 1, through: 0, by: -1) {
            hex += String(format: "%08x", key[i])
        }
        return hex
    }
}

VanityGenerator.main()
