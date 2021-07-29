check log:
$ journalctl --since "1 hour ago" | grep kernel

check kerenl function by ftrace
$ sudo trace-cmd record -p function_graph pidof cron
watch report
$ trace-cmd report | less
