import subprocess
import psutil
import time
import csv
import pandas as pd
import matplotlib.pyplot as plt

executables = [
    ("GPU", "program1.exe"),
    ("CPU", "program2.exe"),
    ("CPUOptimized", "program3.exe")
]

with open("inputs.txt", "r") as f_input:
    inputs = [line.strip() for line in f_input if line.strip()]

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
        row = [input_data]

        for name, exe in executables:
            try:
                process = subprocess.Popen(
                    [exe],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                proc = psutil.Process(process.pid)
                start = time.perf_counter()
                stdout, stderr = process.communicate(input=input_data)
                end = time.perf_counter()
                exec_time = end - start

                try:
                    mem_kb = proc.memory_info().peak_wset / 1024
                except Exception:
                    mem_kb = 0

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
plt.plot(x, df["GPU Time(s)"], label="Program 1", marker='o')
plt.plot(x, df["CPU Time(s)"], label="Program 2", marker='s')
plt.plot(x, df["CPUOptimized Time(s)"], label="Program 3", marker='^')
plt.title("Execution Time per Input")
plt.xlabel("Inputs")
plt.ylabel("Time(s)")
plt.xticks(ticks=x.index, labels=x, rotation=270)
plt.legend()
plt.tight_layout()
plt.savefig("execution_time_plot.png")
plt.show()

plt.figure(figsize=(10, 6))
plt.plot(x, df["GPU Memory(KB)"], label="Program 1", marker='o')
plt.plot(x, df["CPU Memory(KB)"], label="Program 2", marker='s')
plt.plot(x, df["CPUOptimized Memory(KB)"], label="Program 3", marker='^')
plt.title("Memory Usage per Input")
plt.xlabel("Inputs")
plt.ylabel("Memory(KB)")
plt.xticks(ticks=x.index, labels=x, rotation=270)
plt.legend()
plt.tight_layout()
plt.savefig("memory_usage_plot.png")
plt.show()