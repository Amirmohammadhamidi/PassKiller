import subprocess
import psutil
import time
import csv
import pandas as pd
import matplotlib.pyplot as plt
import threading

executables = [
    ("CPU", "CPU/CPU.exe"),
    ("CPUOptimized", "OPTIMIZEDCPU/CPUOptimized.exe")
    # ("GPU", "program3.exe")
]

def get_peak_memory_and_time(exe_path, input_data):
    def monitor(proc, peak_mem):
        peak = 0
        try:
            while proc.is_running():
                try:
                    mem = proc.memory_info().rss
                    peak = max(peak, mem)
                except psutil.NoSuchProcess:
                    break
                time.sleep(0.01)
        except:
            pass
        peak_mem.append(peak)
    print(f"luanching: {exe_path}")
    process = subprocess.Popen(
        [exe_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    proc = psutil.Process(process.pid)
    peak_mem = []
    
    t = threading.Thread(target=monitor, args=(proc, peak_mem))
    t.start()
    
    start = time.perf_counter()
    stdout, stderr = process.communicate(input=input_data + "\n")
    print("[log]", stdout)
    end = time.perf_counter()
    
    t.join()

    exec_time = end - start
    mem_kb = peak_mem[0] / 1024 if peak_mem else 0
    
    return exec_time, mem_kb

with open("inputs.txt", "r") as f:
    inputs = [line.strip() for line in f if line.strip()]

with open("results.csv", mode="w", newline='') as file:
    writer = csv.writer(file)

    header = ["Input"]
    for name, _ in executables:
        header.extend([
            f"{name} Time(s)",
            f"{name} Memory(KB)"
        ])
    writer.writerow(header)

    for input_data in inputs:
        print(input_data)
        row = [input_data]
        for name, exe in executables:
            try:
                exec_time, mem_kb = get_peak_memory_and_time(exe, input_data)
                row.extend([
                    f"{exec_time:.6f}",
                    f"{mem_kb:.2f}"
                ])
            except Exception as e:
                row.extend(["ERROR", "ERROR"])
                print(f"⚠️ Error with {exe} and input '{input_data}': {e}")
        writer.writerow(row)


df = pd.read_csv("results.csv")

x = df["Input"]

for col in df.columns:
    if col != "Input":
        df[col] = pd.to_numeric(df[col], errors='coerce')

plt.figure(figsize=(10, 6))
# plt.plot(x, df["GPU Time(s)"], label="GPU", marker='o')
plt.plot(x, df["CPU Time(s)"], label="CPU", marker='s')
plt.plot(x, df["CPUOptimized Time(s)"], label="CPUOPTIMIZED", marker='^')
plt.title("Execution Time per Input")
plt.xlabel("Inputs")
plt.ylabel("Time(s)")
plt.xticks([])
plt.legend()
plt.tight_layout()
plt.savefig("execution_time_plot.png")
plt.show()

plt.figure(figsize=(10, 6))
# plt.plot(x, df["GPU Memory(KB)"], label="GPU", marker='o')
plt.plot(x, df["CPU Memory(KB)"], label="CPU", marker='s')
plt.plot(x, df["CPUOptimized Memory(KB)"], label="CPUOPTIMIZED", marker='^')
plt.title("Memory Usage per Input")
plt.xlabel("Inputs")
plt.ylabel("Memory(KB)")
plt.xticks([])
plt.legend()
plt.tight_layout()
plt.savefig("memory_usage_plot.png")
plt.show()