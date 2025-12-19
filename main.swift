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

    @Option(name: .shortAndLong, help: "Iterations per GPU thread (default: 1 for safety)")
    var iterations: Int = 1

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
        let shaderPath = Bundle.main.path(forResource: "shader", ofType: "metallib")
            ?? "./shader.metallib"

        let library: MTLLibrary
        do {
            library = try device.makeLibrary(filepath: shaderPath)
        } catch {
            // Try compiling from source
            let sourcePath = "./shader.metal"
            let sourceCode = try String(contentsOfFile: sourcePath, encoding: .utf8)
            library = try device.makeLibrary(source: sourceCode, options: nil)
        }

        guard let kernel = library.makeFunction(name: "vanity_search") else {
            print("Error: Could not find vanity_search kernel")
            throw ExitCode.failure
        }

        let pipelineState = try device.makeComputePipelineState(function: kernel)
        guard let commandQueue = device.makeCommandQueue() else {
            print("Error: Could not create command queue")
            throw ExitCode.failure
        }

        // Calculate thread configuration
        // Start conservative - EC math is expensive
        let maxThreadsPerGroup = pipelineState.maxTotalThreadsPerThreadgroup
        let threadGroupSize = MTLSize(width: min(256, maxThreadsPerGroup), height: 1, depth: 1)
        let numThreadGroups = 64  // Conservative for heavy EC workload
        let totalThreads = numThreadGroups * threadGroupSize.width

        print("Launching \(totalThreads) GPU threads, \(iterations) iterations each")
        print("(Note: secp256k1 scalar mult is expensive, expect ~1-10K keys/sec)")
        print("")

        // Prepare buffers
        // Seeds buffer - 4 x uint64 per thread
        let seedsSize = totalThreads * 4 * MemoryLayout<UInt64>.size
        guard let seedsBuffer = device.makeBuffer(length: seedsSize, options: .storageModeShared) else {
            print("Error: Could not allocate seeds buffer")
            throw ExitCode.failure
        }

        // Initialize with random seeds
        let seedsPtr = seedsBuffer.contents().bindMemory(to: UInt64.self, capacity: totalThreads * 4)
        for i in 0..<(totalThreads * 4) {
            seedsPtr[i] = UInt64.random(in: 0...UInt64.max)
        }

        // Results buffer - space for max_results private keys (4 x uint64 each)
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

        // Prefix buffer - convert hex string to bytes
        let prefixBytes = hexStringToBytes(prefix)
        let prefixLen = UInt32(prefix.count)  // Length in nibbles
        guard let prefixBuffer = device.makeBuffer(bytes: prefixBytes, length: prefixBytes.count, options: .storageModeShared) else {
            print("Error: Could not allocate prefix buffer")
            throw ExitCode.failure
        }

        // Constant buffers
        var prefixLenVal = prefixLen
        var maxResultsVal = UInt32(maxResults)
        var iterationsVal = UInt32(iterations)

        let startTime = Date()
        var totalIterations: UInt64 = 0
        var foundResults = 0

        // Main loop - keep dispatching until we find enough
        while foundResults < count {
            guard let commandBuffer = commandQueue.makeCommandBuffer(),
                  let encoder = commandBuffer.makeComputeCommandEncoder() else {
                continue
            }

            encoder.setComputePipelineState(pipelineState)
            encoder.setBuffer(seedsBuffer, offset: 0, index: 0)
            encoder.setBuffer(resultsBuffer, offset: 0, index: 1)
            encoder.setBuffer(foundCountBuffer, offset: 0, index: 2)
            encoder.setBuffer(prefixBuffer, offset: 0, index: 3)
            encoder.setBytes(&prefixLenVal, length: MemoryLayout<UInt32>.size, index: 4)
            encoder.setBytes(&maxResultsVal, length: MemoryLayout<UInt32>.size, index: 5)
            encoder.setBytes(&iterationsVal, length: MemoryLayout<UInt32>.size, index: 6)

            let gridSize = MTLSize(width: totalThreads, height: 1, depth: 1)
            encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
            encoder.endEncoding()

            commandBuffer.commit()
            commandBuffer.waitUntilCompleted()

            totalIterations += UInt64(totalThreads) * UInt64(iterations)
            foundResults = Int(foundCountBuffer.contents().bindMemory(to: UInt32.self, capacity: 1).pointee)

            // Regenerate seeds for next batch
            for i in 0..<(totalThreads * 4) {
                seedsPtr[i] = UInt64.random(in: 0...UInt64.max)
            }

            // Print progress
            let elapsed = Date().timeIntervalSince(startTime)
            let rate = Double(totalIterations) / elapsed
            print("\rProgress: \(foundResults)/\(count) found, \(String(format: "%.2f", rate / 1_000_000))M keys/sec", terminator: "")
            fflush(stdout)
        }

        print("\n---")

        // Read results
        let resultsPtr = resultsBuffer.contents().bindMemory(to: UInt64.self, capacity: maxResults * 4)
        for i in 0..<count {
            let limbs = (
                resultsPtr[i * 4 + 0],
                resultsPtr[i * 4 + 1],
                resultsPtr[i * 4 + 2],
                resultsPtr[i * 4 + 3]
            )

            let privateKeyHex = String(format: "0x%016llx%016llx%016llx%016llx",
                                       limbs.3, limbs.2, limbs.1, limbs.0)

            // Derive address (simplified - would need full EC math to verify)
            print("Found #\(i + 1): Private Key = \(privateKeyHex)")
        }

        let elapsed = Date().timeIntervalSince(startTime)
        print("---")
        print(String(format: "Generated %d addresses in %.2fs (%.2fM keys/sec)",
                     count, elapsed, Double(totalIterations) / elapsed / 1_000_000))
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
