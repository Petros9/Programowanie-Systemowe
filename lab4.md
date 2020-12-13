# Programowanie Systemowe<br/> Debugowanie jądra - sprawozdanie<br/>Piotr Świderski śr 12:50 - 14:40

## 1. Debugowanie modułów
   1. Moduł 1
        
        Moduł został załadowany:
        ```
        [   298.506783] broken_module: loading out-of-tree module tains kernel.
        [   298.506896] The BROKEN module has been inserted
        ```
        Wywołana została komenda `cat /dev/broken` (operacja została zabita)

        ```
        [student@ps2017 dev]$ sudo cat /dev/broken
        Killed
        ```
        Przydatne informacje uzyskane po wywołaniu komendy `dmesg`:
        ```
        [   2398.704348] Call Trace:
        [   2398.704353] [<ffffffffffffffc07cb354>] broken_read+0x150/0x195 [broken_module]      
        ```

        ```
        [   2398.704379] RIP [<ffffffffffffffbc230653>] kfree+0x53/0x170
        ```

        Z powyższych komunikatów można wywnioskować, że problem pojawił się przy wywoływaniu funkcji kfree() w funkcji broken_read().

        Funkcja broken_read():

        ```
        ssize_t broken_read(struct file *filp, char *user_buf, size_t count,loff_t *f_pos)
        {
 	        char *mybuf = NULL;
            int mybuf_size = 100;
	        int len, err;
	        mybuf = kmalloc(mybuf_size, GFP_KERNEL);

	        if (!mybuf) {
                return -ENOMEM;
            }

	        fill_buffer(mybuf, mybuf_size);
	        len = strlen(mybuf);
	        err = copy_to_user(user_buf, mybuf, len);
	        kfree(mybuf); // było kfree(user_buf);
	        read_count++;

            if (!err && *f_pos == 0) {
                *f_pos += len;
                return len;
	        }
            return 0;
        }
        ```
  
 W miejscu oznaczonym "//" znajdował się wskaźnik na przestrzeń użytkownika, a wydaje się, że powinien być zwalniany zaalokowany wcześniej w samej funkcji bufor "mybuf".

 W module znajdowała się także nic nie robiąca funkcja `broken_write`, a najpewniej powinna służyć do zliczania zapisów do /dev/broken, więc została ona zmodyfikowana w następujący sposób:

    ```
   ssize_t broken_write(struct file *filp, const char *user_buf, size_t count,loff_t *f_pos)
    {
      	write_count++; // wcześniej tu tego nie było
       return 1;
   }
    ```

Po wprowadzeniu modyfikacji przetestowano poprawność działania modułu:

   ```
   [root@ps2017 ~]$ echo "test" > /dev/broken
   [root@ps2017 ~]$ echo "szklanka" > /dev/broken
   [root@ps2017 ~]$ cat /dev/broken
   I've created a buffer of size: 100
   [root@ps2017 ~]$ cat /proc/broken | head -2
   BROKEN. Reads: 2, Writes: 14
   BROKEN. Reads: 2, Writes: 14
   ```

   2. Moduł 2
   3. Moduł 3
   4. Moduł 4

## 2. GDB
   1. `/proc/loadavg`
   2. `proc/PID/fd`
   3. `proc/PID/environ`
