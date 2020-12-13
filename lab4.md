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


    ssize_t broken_write(struct file *filp, const char *user_buf, size_t count,loff_t *f_pos)
    {
      	write_count++; // wcześniej tu tego nie było
        return 1;
    }


Po wprowadzeniu modyfikacji przetestowano poprawność działania modułu:


    [root@ps2017 ~]$ echo "test" > /dev/broken
    [root@ps2017 ~]$ echo "szklanka" > /dev/broken
    [root@ps2017 ~]$ cat /dev/broken
    I've created a buffer of size: 100
    [root@ps2017 ~]$ cat /proc/broken | head -2
    BROKEN. Reads: 2, Writes: 14
    BROKEN. Reads: 2, Writes: 14


   2. Moduł 2
   Postąpiono podobnie jak poprzednio, komunikaty po wywołaniu `cat /dev/broken`:
   
       [root@ps2017 2]# cat /dev/broken
       Killed
       
   Oraz `dmesg`:
   
   `
        [  3466.319942] BUG: unable to handle kernel NULL pointer dereference at (null)
        [  3487.771975] IP: [<fffffffffffffbc4031fd>] memcpy_orig+0x9d/0x110   
    `
    Jak widać nastąpiło odwołanie do adresu null wewnątrz funkcji memcpy(). Możliwe, że przekazano do jakiejś funkcji jądra niezainicjolizowany wskaźnik.
    
   Sekcji Call Trace:
   ```
        [  3487.772163] Call Trace:
        [  3487.772172] [<fffffffffffffbc400f5b>] ? vsnprintf+-xeb/0x500
        [  3487.772214] [<fffffffffffffbc401506>] sprintf+0x56/0x70
        [  3487.772220] [<fffffffffffffbc22fbf9>] ? kmem_cache_alloc_trace+0x159/0x1b0
        [  3487.772223] [<fffffffffffffbc07c6225] fill_buffer+0x1e/0x30 [broken_module]
        [  3487.772227] [<fffffffffffffbc258db7>] broken_read+0x45/0xe20 [broken_module] 
   ```
   Na stosie wywołań widać funkcje `fill_buffer()` oraz `broken_read()`. Najpewniej gdzieś tutaj znajduje się błąd.
   
   Funkcja `fill_buffer()`:
   ```
   	int fill_buffer(char *buf, int buf_size)
	{
        	sprintf(buf, "I've created a buffer of size: %d\n", buf_size);
        	return strlen(buf); // było strlen(mybuf) który nie był ani przekazywany ani inicjalizowany w funkcji.
	}
   ```
   
   Wyniki testowe wyglądały tak samo jak w module nr 1, który znajduje się powyżej.
   
   3. Moduł 3
   4. Moduł 4

## 2. GDB
   1. `/proc/loadavg`
   2. `proc/PID/fd`
   3. `proc/PID/environ`
