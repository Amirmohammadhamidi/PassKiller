#pragma once
#ifdef __cplusplus
extern "C"
{
#endif

    void runSHA256BruteForceKernel(const char *targetHash, char *foundCandidate, bool *found, int numCandidates);

#ifdef __cplusplus
}
#endif