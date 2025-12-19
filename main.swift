import Foundation
import Metal
import ArgumentParser

struct VanityGenerator: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "vanity_metal",
        abstract: "GPU-accelerated vanity Ethereum address generator for Apple Silicon"
    )

    @Option(name: .shortAndLong, help: "Number of addresses to generate")
    var count: Int = 10

    @Option(name: .shortAndLong, help: "Address prefix to match (without 0x)")
    var prefix: String = "badbad"

    @Option(name: .shortAndLong, help: "Iterations per GPU thread")
    var iterations: Int = 1000

    @Option(name: .shortAndLong, help: "Number of GPU threads")
    var threads: Int = 16384

    func run() throws {
        print("Vanity Address Generator (Metal/Apple Silicon)")
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
            // Try loading precompiled metallib first
            if FileManager.default.fileExists(atPath: "./shader.metallib") {
                library = try device.makeLibrary(filepath: "./shader.metallib")
            } else {
                // Fall back to compiling from source
                let sourceCode = try String(contentsOfFile: "./shader.metal", encoding: .utf8)
                library = try device.makeLibrary(source: sourceCode, options: nil)
            }
        } catch {
            print("Error loading shader: \(error)")
            throw ExitCode.failure
        }

        // Get both kernels
        guard let precomputeKernel = library.makeFunction(name: "compute_public_key"),
              let searchKernel = library.makeFunction(name: "vanity_search") else {
            print("Error: Could not find kernel functions")
            throw ExitCode.failure
        }

        let precomputePipeline = try device.makeComputePipelineState(function: precomputeKernel)
        let searchPipeline = try device.makeComputePipelineState(function: searchKernel)

        guard let commandQueue = device.makeCommandQueue() else {
            print("Error: Could not create command queue")
            throw ExitCode.failure
        }

        // Thread configuration
        let totalThreads = threads
        let maxThreadsPerGroup = searchPipeline.maxTotalThreadsPerThreadgroup
        let threadGroupSize = MTLSize(width: min(256, maxThreadsPerGroup), height: 1, depth: 1)

        print("Using \(totalThreads) GPU threads, \(iterations) iterations each")
        print("Optimization: Precompute public keys, then increment with P+G")
        print("")

        // Allocate buffers
        // Private keys: 4 x uint64 per thread
        let keysSize = totalThreads * 4 * MemoryLayout<UInt64>.size
        guard let privateKeysBuffer = device.makeBuffer(length: keysSize, options: .storageModeShared) else {
            print("Error: Could not allocate private keys buffer")
            throw ExitCode.failure
        }

        // Public points: 8 x uint64 per thread (x and y coordinates)
        let pointsSize = totalThreads * 8 * MemoryLayout<UInt64>.size
        guard let publicPointsBuffer = device.makeBuffer(length: pointsSize, options: .storageModeShared) else {
            print("Error: Could not allocate public points buffer")
            throw ExitCode.failure
        }

        // Results buffer
        let maxResults = count
        let resultsSize = maxResults * 4 * MemoryLayout<UInt64>.size
        guard let resultsBuffer = device.makeBuffer(length: resultsSize, options: .storageModeShared) else {
            print("Error: Could not allocate results buffer")
            throw ExitCode.failure
        }

        // Found count buffer
        guard let foundCountBuffer = device.makeBuffer(length: MemoryLayout<UInt32>.size, options: .storageModeShared) else {
            print("Error: Could not allocate found count buffer")
            throw ExitCode.failure
        }
        foundCountBuffer.contents().bindMemory(to: UInt32.self, capacity: 1).pointee = 0

        // Prefix buffer
        let prefixBytes = hexStringToBytes(prefix)
        let prefixLen = UInt32(prefix.count)
        guard let prefixBuffer = device.makeBuffer(bytes: prefixBytes, length: max(prefixBytes.count, 1), options: .storageModeShared) else {
            print("Error: Could not allocate prefix buffer")
            throw ExitCode.failure
        }

        var prefixLenVal = prefixLen
        var maxResultsVal = UInt32(maxResults)
        var iterationsVal = UInt32(iterations)

        let startTime = Date()
        var totalKeysChecked: UInt64 = 0
        var foundResults = 0
        var batchCount = 0

        // Main loop
        while foundResults < count {
            batchCount += 1

            // Step 1: Generate random private keys
            let keysPtr = privateKeysBuffer.contents().bindMemory(to: UInt64.self, capacity: totalThreads * 4)
            for i in 0..<(totalThreads * 4) {
                keysPtr[i] = UInt64.random(in: 0...UInt64.max)
            }

            // Step 2: Precompute public keys on GPU (one-time cost per batch)
            if let commandBuffer = commandQueue.makeCommandBuffer(),
               let encoder = commandBuffer.makeComputeCommandEncoder() {

                encoder.setComputePipelineState(precomputePipeline)
                encoder.setBuffer(privateKeysBuffer, offset: 0, index: 0)
                encoder.setBuffer(publicPointsBuffer, offset: 0, index: 1)

                let gridSize = MTLSize(width: totalThreads, height: 1, depth: 1)
                encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
                encoder.endEncoding()

                commandBuffer.commit()
                commandBuffer.waitUntilCompleted()
            }

            // Step 3: Run the optimized search kernel
            if let commandBuffer = commandQueue.makeCommandBuffer(),
               let encoder = commandBuffer.makeComputeCommandEncoder() {

                encoder.setComputePipelineState(searchPipeline)
                encoder.setBuffer(publicPointsBuffer, offset: 0, index: 0)
                encoder.setBuffer(privateKeysBuffer, offset: 0, index: 1)
                encoder.setBuffer(resultsBuffer, offset: 0, index: 2)
                encoder.setBuffer(foundCountBuffer, offset: 0, index: 3)
                encoder.setBuffer(prefixBuffer, offset: 0, index: 4)
                encoder.setBytes(&prefixLenVal, length: MemoryLayout<UInt32>.size, index: 5)
                encoder.setBytes(&maxResultsVal, length: MemoryLayout<UInt32>.size, index: 6)
                encoder.setBytes(&iterationsVal, length: MemoryLayout<UInt32>.size, index: 7)

                let gridSize = MTLSize(width: totalThreads, height: 1, depth: 1)
                encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
                encoder.endEncoding()

                commandBuffer.commit()
                commandBuffer.waitUntilCompleted()
            }

            totalKeysChecked += UInt64(totalThreads) * UInt64(iterations)
            foundResults = Int(foundCountBuffer.contents().bindMemory(to: UInt32.self, capacity: 1).pointee)

            // Print progress
            let elapsed = Date().timeIntervalSince(startTime)
            let rate = Double(totalKeysChecked) / elapsed
            print("\rBatch \(batchCount): \(foundResults)/\(count) found, \(String(format: "%.2f", rate / 1_000_000))M keys/sec, \(String(format: "%.1f", elapsed))s elapsed", terminator: "")
            fflush(stdout)
        }

        print("\n---")

        // Read and display results
        let resultsPtr = resultsBuffer.contents().bindMemory(to: UInt64.self, capacity: maxResults * 4)
        for i in 0..<count {
            let limbs = (
                resultsPtr[i * 4 + 0],
                resultsPtr[i * 4 + 1],
                resultsPtr[i * 4 + 2],
                resultsPtr[i * 4 + 3]
            )

            // Format as big-endian hex (most significant limb first)
            let privateKeyHex = String(format: "0x%016llx%016llx%016llx%016llx",
                                       limbs.3, limbs.2, limbs.1, limbs.0)

            print("Found #\(i + 1): Private Key = \(privateKeyHex)")
        }

        let elapsed = Date().timeIntervalSince(startTime)
        print("---")
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
}

VanityGenerator.main()
