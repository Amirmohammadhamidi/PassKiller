#include <cuda_runtime.h>
#include <stdio.h>
#include <string>
#include "HashCrackerEngine.hpp" // Provides SHA256 and swapEndian
#include "SHA256GPUKernel.h"
#include "SHA256Device.h"

__constant__ char d_charset[73] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

__global__ void sha256BruteForceKernel(const uint32_t *__restrict__ d_targetHash,
                                       char *__restrict__ d_foundCandidate,
                                       bool *__restrict__ d_found,
                                       int numCandidates)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= numCandidates || *d_found)
        return;

    char candidate[6];
    int temp = idx;
#pragma unroll
    for (int i = 4; i >= 0; i--)
    {
        candidate[i] = d_charset[temp % 72];
        temp /= 72;
    }
    candidate[5] = '\0';

    uint32_t computedHash[8];
    deviceSHA256(candidate, computedHash);

    bool match = true;
#pragma unroll
    for (int i = 0; i < 8; i++)
    {
        if (computedHash[i] != d_targetHash[i])
        {
            match = false;
            break;
        }
    }

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

extern "C" void runSHA256BruteForceKernel(const char *targetHash, char *foundCandidate, bool *found, int numCandidates)
{
    uint32_t h_target[8];
    for (int i = 0; i < 8; i++)
    {
        h_target[i] = std::stoul(std::string(targetHash).substr(i * 8, 8), nullptr, 16);
        h_target[i] = SHA256::swapEndian(h_target[i]);
    }

    uint32_t *d_targetHash;
    cudaMalloc(&d_targetHash, 8 * sizeof(uint32_t));
    cudaMemcpy(d_targetHash, h_target, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice);

    char *d_foundCandidate;
    bool *d_found;
    cudaMalloc(&d_foundCandidate, 6 * sizeof(char));
    cudaMalloc(&d_found, sizeof(bool));

    bool initFound = false;
    cudaMemcpy(d_found, &initFound, sizeof(bool), cudaMemcpyHostToDevice);

    int blockSize = 1024;
    int gridSize = (numCandidates + blockSize - 1) / blockSize;

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    sha256BruteForceKernel<<<gridSize, blockSize>>>(d_targetHash, d_foundCandidate, d_found, numCandidates);
    cudaDeviceSynchronize();

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float ms = 0.0f;
    cudaEventElapsedTime(&ms, start, stop);
    printf("Kernel time: %.2f ms\n", ms);

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
