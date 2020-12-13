# Programowanie Systemowe<br/> Debugowanie jądra - sprawozdanie<br/>Piotr Świderski śr 12:50 - 14:40

## 1. Debugowanie modułów
 **1. Moduł 1**
        
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


 **2. Moduł 2**
  
   Postąpiono podobnie jak poprzednio, komunikaty po wywołaniu `cat /dev/broken`:
   
       [root@ps2017 2]# cat /dev/broken
       Killed
       
   Oraz `dmesg`:
   
   ```
        [  3466.319942] BUG: unable to handle kernel NULL pointer dereference at (null)
        [  3487.771975] IP: [<fffffffffffffbc4031fd>] memcpy_orig+0x9d/0x110   
   ```
    
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
   
 **3. Moduł 3**
 
   Podobnie jak w powyższych przykładach moduł został skompilowany i załadowany. Wywołana została komenda `echo 2315 > /dev/broken`, gdzie 2315 było numerem PID powłoki bashowej, czym uzyskano taki wynik:
   
   ```
   [root@ps2017 3]# echo 2315 > dev/broken
   Killed
   ```
   Ponadto wyłączony został tryb root. Użycie komendy `dmesg` dało następujące rezultaty:
   
   ```
   [   301.506783] The BROKEN module has been inserted
   [   361.625998] perf: interrupt took to long (2511 > 2500), lowering kernel.perf_event_max_sample_rate to 79000  
   [   408.976783] BUG: unable to handle kernel NULL pointer dereference ar 0000000000090b
   [   408.976997] IP: [<ffffffffa53fd19e>] strcpy+0xe/0x20
   ```
   Oraz:
   ```
   [   408.976794] Call Trace:
   [   408.976911] [<ffffffffc09fd304>] fill_buffer_with_process_name+0x34/0x50 [broken_module]
   [   408.989111] [<ffffffffc069d398>] broke_write+078/0xce0 [broken_module]
   ```
   Można z tego wywnioskować, że błąd dotyczył funkcji `strcpy()`, którą wywołała funkcja      `fill_buffer_with_process_name()`, którą wywołała funkcja `broken_write()`
   
   Funkcja `fill_buffer_with_process_name()`:
   
   ```
   void fill_buffer_with_process_name(long pid)
   {
        struct pid *selected_pid = find_get_pid(pid);
        struct task_struct *selected_proc = pid_task(selected_pid, PIDTYPE_PID);

        if (selected_proc != NULL)
                strcpy(buf1, (char *) selected_proc->comm); // było tutaj selected_proc->pid
	else
                sprintf(buf1, "The process with PID: %ld cannot be found", pid);
   }
   ```
   PID jest liczbą, a w powyższej funkcji był wykorzytywany jako wskaźnik. Docelowo w buf1 powinna się znaleźć nazwa procesu, która zajduje się w tablice comm[].
   
 Po naprawie moduł działał w następujący sposób:
 ```
    [root@ps2017 3]# echo 3860 > dev/broken
    [root@ps2017 3]# cat dev/broken
    Process name: bash
 ```
   
 **4. Moduł 4**

Podobnie jak w powyższych przykładach moduł został skompilowany i załadowany. Wywołana została komenda `echo "abcd123" > /dev/broken` uzyskano taki wynik:

```
[root@ps2017 4]# insmod broken_module.ko
[root@ps2017 4]# mknod /dev/broken c 899 0
[root@ps2017 4]# cat /dev/broken
I've recenlty read 0 numeric characters
[root@ps2017 4]# echo "abcd123" > /dev/broken
Segmentation fault
```
`Call Trace` po wywolaniu `dmesg`:

```
        [  1285.392163] Call Trace:
        [  1285.392199] [<fffffffffffffbc400f44>] broken_write+0x44/0xb0 [broken_module]
```
Można z tego wywnioskować, że problem dotyczył jakiegoś wywołania w funkcji `broken_write()`. Z racji braku lepszych  pomysłów najlepsze wydawało się przeglądanie kolejno wywoływanych funkcji i patrzenie, czy nie występują tam jakieś anomalie. Taką funkcją okazała się `count_numbers()`. Zamiast podanego w argumentach wskaźnika str używano tam wskaźnika ptr ustawionego na NULL. Należało zamienić ptr na str oraz przenieść inkrementację na dół pętli (inaczej nie była by zliczana pierwsza cyfra w napisie). 

Funkcja `int count_numbers()` po poprawie:

```
int count_numbers(char *str)
{
        int numbers = 0;

        while (*str != 0) {
                if (isdigit(*str))
                        numbers++;
                str++;
        }

        return numbers;
}
```

Test działania:

```
[root@ps2017 4]# echo "abcd123" > /dev/broken
[root@ps2017 4]# cat /dev/broken
I've recenlty read 3 numeric characters
```

## 2. GDB
 **1. `/proc/loadavg`**
 **2. `proc/PID/fd`**
 **3. `proc/PID/environ`**
