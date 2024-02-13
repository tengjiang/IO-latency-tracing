# IO-latency-tracing
Simple program using eBPF to trace IO latency.

## Usage
```
make
sudo ./iolatency.out <print time interval>
```

## IO workload generation with ```fio```
```
sudo fio --filename=./text.txt --rw=read --direct=1 --bs=1M --ioengine=libaio --runtime=5 --numjobs=1 --time_based --group_reporting --name=seq_read --size=1M --iodepth=16
```
