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
    var iterations: Int = 255

    @Option(name: .shortAndLong, help: "Number of GPU threads")
    var threads: Int = 65536

    @Option(name: .shortAndLong, help: "Inverse batch size (smaller = better GPU occupancy)")
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
              let combinedKernel = library.makeFunction(name: "profanity_combined") else {
            print("Error: Could not find kernel functions")
            throw ExitCode.failure
        }

        let initPipeline = try device.makeComputePipelineState(function: initKernel)
        let combinedPipeline = try device.makeComputePipelineState(function: combinedKernel)

        guard let commandQueue = device.makeCommandQueue() else {
            print("Error: Could not create command queue")
            throw ExitCode.failure
        }

        // Thread configuration
        let totalThreads = threads
        let maxThreadsPerGroup = combinedPipeline.maxTotalThreadsPerThreadgroup
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

            // Step 3: Run iterations with combined kernel (inverse + iterate in one)
            // Single dispatch per iteration, no barriers needed
            if let commandBuffer = commandQueue.makeCommandBuffer(),
               let encoder = commandBuffer.makeComputeCommandEncoder() {

                let gridSize = MTLSize(width: totalThreads, height: 1, depth: 1)

                // Set constant buffers once
                encoder.setComputePipelineState(combinedPipeline)
                encoder.setBuffer(deltaXBuffer, offset: 0, index: 0)
                encoder.setBuffer(prevLambdaBuffer, offset: 0, index: 1)
                encoder.setBuffer(resultsBuffer, offset: 0, index: 2)
                encoder.setBuffer(foundCountBuffer, offset: 0, index: 3)
                encoder.setBuffer(prefixBuffer, offset: 0, index: 4)
                encoder.setBytes(&prefixLenVal, length: MemoryLayout<UInt32>.size, index: 5)
                encoder.setBytes(&maxResultsVal, length: MemoryLayout<UInt32>.size, index: 6)
                encoder.setBuffer(iterCounterBuffer, offset: 0, index: 7)

                for _ in 0..<iterations {
                    encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
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

                for i in foundResults..<min(newFoundCount, count) {
                    let threadId = Int(resultsPtr[i * 2])
                    let iteration = Int(resultsPtr[i * 2 + 1])

                    // Recover private key: original key + iteration offset
                    if threadId < storedPrivateKeys.count {
                        var privateKey = storedPrivateKeys[threadId]
                        // Add iteration + 1 to get the actual key (iteration 0 = first point after init)
                        addToKey(&privateKey, UInt64(iteration + 1))
                        let hexKey = formatKeyAsHex(privateKey)
                        print("\nFound #\(i + 1): Private Key = \(hexKey)")
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
