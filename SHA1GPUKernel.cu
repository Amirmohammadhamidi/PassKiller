#include <cuda_runtime.h>
#include <stdio.h>
#include <string>
#include "HashCrackerEngine.hpp" // Provides swapEndian
#include "SHA1GPUKernel.h"
#include "SHA1Device.h" // Uses deviceSHA1

// Character set stored in constant memory.
__constant__ char d_charset[73] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

// CUDA kernel for SHA-1 brute-force.
__global__ void sha1BruteForceKernel(const uint32_t *__restrict__ d_targetHash,
                                     char *__restrict__ d_foundCandidate,
                                     bool *__restrict__ d_found,
                                     int numCandidates)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= numCandidates || *d_found)
        return;

    // Generate a 5-character candidate.
    char candidate[6];
    int temp = idx;
#pragma unroll
    for (int i = 4; i >= 0; i--)
    {
        candidate[i] = d_charset[temp % 72];
        temp /= 72;
    }
    candidate[5] = '\0';

    // Compute SHA-1 hash.
    uint32_t computedHash[5];
    deviceSHA1(candidate, computedHash);

    // Compare hash with target.
    bool match = true;
#pragma unroll
    for (int i = 0; i < 5; i++)
    {
        if (computedHash[i] != d_targetHash[i])
        {
            match = false;
            break;
        }
    }

    // If match, store candidate.
    if (match)
    {
        *d_found = true;
#pragma unroll
        for (int i = 0; i < 5; i++)
        {
            d_foundCandidate[i] = candidate[i];
        }
        d_foundCandidate[5] = '\0';
    }
}

extern "C" void runSHA1BruteForceKernel(const char *targetHash, char *foundCandidate, bool *found, int numCandidates)
{
    // Parse hex SHA-1 hash (40 chars => 5 * 32-bit words)
    uint32_t h_target[5];
    for (int i = 0; i < 5; i++)
    {
        h_target[i] = std::stoul(std::string(targetHash).substr(i * 8, 8), nullptr, 16);
        h_target[i] = SHA1::swapEndian(h_target[i]);
    }

    // Allocate GPU memory
    uint32_t *d_targetHash;
    cudaMalloc(&d_targetHash, 5 * sizeof(uint32_t));
    cudaMemcpy(d_targetHash, h_target, 5 * sizeof(uint32_t), cudaMemcpyHostToDevice);

    char *d_foundCandidate;
    bool *d_found;
    cudaMalloc(&d_foundCandidate, 6 * sizeof(char));
    cudaMalloc(&d_found, sizeof(bool));

    bool initFound = false;
    cudaMemcpy(d_found, &initFound, sizeof(bool), cudaMemcpyHostToDevice);

    // Launch kernel
    int blockSize = 1024;
    int gridSize = (numCandidates + blockSize - 1) / blockSize;

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    sha1BruteForceKernel<<<gridSize, blockSize>>>(d_targetHash, d_foundCandidate, d_found, numCandidates);
    cudaDeviceSynchronize();

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float ms = 0.0f;
    cudaEventElapsedTime(&ms, start, stop);
    printf("SHA-1 Kernel time: %.2f ms\n", ms);

    // Retrieve result
    bool h_found;
    cudaMemcpy(&h_found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
    if (h_found)
    {
        cudaMemcpy(foundCandidate, d_foundCandidate, 6 * sizeof(char), cudaMemcpyDeviceToHost);
        *found = true;
    }

    cudaFree(d_targetHash);
    cudaFree(d_foundCandidate);
    cudaFree(d_found);
}
