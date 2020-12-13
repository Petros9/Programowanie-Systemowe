# Programowanie Systemowe<br/> Debugowanie jądra - sprawozdanie<br/>Piotr Świderski śr 12:50 - 14:40

## 1. Debugowanie modułów
   1. Moduł 1
        
        Moduł został załadowany:
        ```
        [   298.506783] broken_module: loading out-of-tree module tains kernel.
        [   298.506896] The BROKEN module has been inserted
        ```
        Wywołana została komenda `cat /dev/broken` //operacja została zabita

        ```
        [student@ps2017 dev]$ sudo cat /dev/broken
        Killed
        ```


   2. Moduł 2
   3. Moduł 3
   4. Moduł 4

## 2. GDB
   1. `/proc/loadavg`
   2. `proc/PID/fd`
   3. `proc/PID/environ`
