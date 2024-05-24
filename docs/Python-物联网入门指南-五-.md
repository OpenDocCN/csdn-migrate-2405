# Python 物联网入门指南（五）

> 原文：[`zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06`](https://zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：文件 I/O 和 Python 工具

在本章中，我们将详细讨论文件 I/O，即读取、写入和追加文件。我们还将讨论 Python 工具，这些工具使得操作文件和与操作系统交互成为可能。每个主题都有不同的复杂程度，我们将通过一个例子来讨论。让我们开始吧！

# 文件 I/O

我们讨论文件 I/O 有两个原因：

+   在 Linux 操作系统的世界中，一切都是文件。与树莓派上的外围设备交互类似于读取/写入文件。例如：在第十二章中，*通信接口*，我们讨论了串口通信。您应该能够观察到串口通信类似于文件读写操作。

+   我们在每个项目中以某种形式使用文件 I/O。例如：将传感器数据写入 CSV 文件，或者读取 Web 服务器的预配置选项等。

因此，我们认为讨论 Python 中的文件 I/O 作为一个单独的章节会很有用（详细文档请参阅：[`docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files`](https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files)），并讨论它在开发树莓派 Zero 应用程序时可能发挥作用的示例。

# 从文件中读取

让我们创建一个简单的文本文件`read_file.txt`，其中包含以下文本：`我正在使用树莓派 Zero 学习 Python 编程`，并将其保存到代码示例目录（或您选择的任何位置）。

要从文件中读取，我们需要使用 Python 的内置函数：`open`来打开文件。让我们快速看一下一个代码片段，演示如何打开一个文本文件以读取其内容并将其打印到屏幕上：

```py
if __name__ == "__main__":
    # open text file to read
    file = open('read_line.txt', 'r')
    # read from file and store it to data
    data = file.read()
    print(data)
    file.close()
```

让我们详细讨论这段代码片段：

1.  读取文本文件内容的第一步是使用内置函数`open`打开文件。需要将所需的文件作为参数传递，并且还需要一个标志`r`，表示我们打开文件以读取内容（随着我们讨论每个读取/写入文件时，我们将讨论其他标志选项）。

1.  打开文件时，`open`函数返回一个指针（文件对象的地址），并将其存储在`file`变量中。

```py
       file = open('read_line.txt', 'r')
```

1.  这个文件指针用于读取文件的内容并将其打印到屏幕上：

```py
       data = file.read() 
       print(data)
```

1.  读取文件的内容后，通过调用`close()`函数关闭文件。

运行前面的代码片段（可与本章一起下载的`read_from_file.py`）使用 IDLE3 或命令行终端。文本文件的内容将如下打印到屏幕上：

```py
    I am learning Python Programming using the Raspberry Pi Zero
```

# 读取行

有时，有必要逐行读取文件的内容。在 Python 中，有两种选项可以做到这一点：`readline()`和`readlines()`：

+   `readline()`: 正如其名称所示，这个内置函数使得逐行读取成为可能。让我们通过一个例子来复习一下：

```py
       if __name__ == "__main__": 
          # open text file to read
          file = open('read_line.txt', 'r') 

          # read a line from the file
          data = file.readline() 
          print(data) 

          # read another line from the file 
          data = file.readline() 
          print(data) 

          file.close()
```

当执行前面的代码片段（可与本章一起下载，文件名为`read_line_from_file.py`）时，`read_line.txt`文件被打开，并且`readline()`函数返回一行。这一行被存储在变量 data 中。由于该函数在程序中被调用两次，输出如下：

```py
 I am learning Python Programming using the Raspberry Pi Zero. 

 This is the second line.
```

每次调用`readline`函数时都会返回一个新行，并且当到达文件结尾时会返回一个空字符串。

+   `readlines()`: 这个函数逐行读取文件的全部内容，并将每一行存储到一个列表中：

```py
       if __name__ == "__main__": 
           # open text file to read
           file = open('read_lines.txt', 'r') 

           # read a line from the file
           data = file.readlines() 
           for line in data: 
               print(line) 

           file.close()
```

由于文件的行被存储为一个列表，可以通过对列表进行迭代来检索它：

```py
       data = file.readlines() 
           for line in data: 
               print(line)
```

前面的代码片段可与本章一起下载，文件名为`read_lines_from_file.py`。

# 写入文件

按照以下步骤进行写入文件：

1.  写入文件的第一步是使用写入标志`w`打开文件。如果作为参数传递的文件名不存在，将创建一个新文件：

```py
      file = open('write_file.txt', 'w')
```

1.  文件打开后，下一步是将要写入的字符串作为参数传递给`write()`函数：

```py
      file.write('I am excited to learn Python using
      Raspberry Pi Zero')
```

1.  让我们将代码放在一起，我们将一个字符串写入文本文件，关闭它，重新打开文件并将文件的内容打印到屏幕上：

```py
       if __name__ == "__main__": 
          # open text file to write
          file = open('write_file.txt', 'w') 
          # write a line from the file
          file.write('I am excited to learn Python using
          Raspberry Pi Zero \n') 
          file.close() 

          file = open('write_file.txt', 'r') 
          data = file.read() 
          print(data) 
          file.close()
```

1.  前面的代码片段可与本章一起下载（`write_to_file.py`）。

1.  当执行前面的代码片段时，输出如下所示：

```py
       I am excited to learn Python using Raspberry Pi Zero
```

# 追加到文件

每当使用写入标志`w`打开文件时，文件的内容都会被删除，并重新打开以写入数据。还有一个叫做`a`的替代标志，它使得可以将数据追加到文件的末尾。如果打开的文件（作为打开的参数）不存在，这个标志也会创建一个新文件。让我们考虑下面的代码片段，我们将一行追加到上一节中的文本文件`write_file.txt`中：

```py
if __name__ == "__main__": 
   # open text file to append
   file = open('write_file.txt', 'a') 
   # append a line from the file
   file.write('This is a line appended to the file\n') 
   file.close() 

   file = open('write_file.txt', 'r') 
   data = file.read() 
   print(data) 
   file.close()
```

当执行前面的代码片段（可与本章一起下载的`append_to_file.py`）时，字符串`This is a line appended to the file`将被追加到文件的文本末尾。文件的内容将包括以下内容：

```py
    I am excited to learn Python using Raspberry Pi Zero
 This is a line appended to the file
```

# 寻找

一旦文件被打开，文件 I/O 中使用的文件指针会从文件的开头移动到文件的末尾。可以将指针移动到特定位置并从该位置读取数据。当我们对文件的特定行感兴趣时，这是非常有用的。让我们考虑上一个例子中的文本文件`write_file.txt`。文件的内容包括：

```py
    I am excited to learn Python using Raspberry Pi Zero
 This is a line appended to the file
```

让我们尝试跳过第一行，只读取第二行，使用`seek`：

```py
if __name__ == "__main__": 
   # open text file to read

   file = open('write_file.txt', 'r') 

   # read the second line from the file
   file.seek(53) 

   data = file.read() 
   print(data) 
   file.close()
```

在前面的例子中（可与本章一起下载的`seek_in_file.py`），`seek`函数用于将指针移动到字节`53`，即第一行的末尾。然后文件的内容被读取并存储到变量中。当执行这个代码片段时，输出如下所示：

```py
    This is a line appended to the file
```

因此，seek 使得移动文件指针到特定位置成为可能。

# 读取 n 个字节

`seek`函数使得将指针移动到特定位置并从该位置读取一个字节或`n`个字节成为可能。让我们重新阅读`write_file.txt`，并尝试读取句子`I am excited to learn Python using Raspberry Pi Zero`中的单词`excited`。

```py
if __name__ == "__main__": 
   # open text file to read and write 
   file = open('write_file.txt', 'r') 

   # set the pointer to the desired position 
   file.seek(5) 
   data = file.read(1) 
   print(data) 

   # rewind the pointer
   file.seek(5) 
   data = file.read(7) 
   print(data) 
   file.close()
```

前面的代码可以通过以下步骤来解释：

1.  第一步，使用`read`标志打开文件，并将文件指针设置为第五个字节（使用`seek`）——文本文件内容中字母`e`的位置。

1.  现在，我们通过将文件作为参数传递给`read`函数来从文件中读取一个字节。当整数作为参数传递时，`read`函数会从文件中返回相应数量的字节。当没有传递参数时，它会读取整个文件。如果文件为空，`read`函数会返回一个空字符串：

```py
       file.seek(5) 
       data = file.read(1) 
       print(data)
```

1.  在第二部分中，我们尝试从文本文件中读取单词`excited`。我们将指针的位置倒回到第五个字节。然后我们从文件中读取七个字节（单词`excited`的长度）。

1.  当执行代码片段时（可与本章一起下载的`seek_to_read.py`），程序应该打印字母`e`和单词`excited`：

```py
       file.seek(5) 
       data = file.read(7) 
       print(data)
```

# r+

我们讨论了使用`r`和`w`标志读取和写入文件。还有另一个叫做`r+`的标志。这个标志使得可以对文件进行读取和写入。让我们回顾一个例子，以便理解这个标志。

让我们再次回顾`write_file.txt`的内容：

```py
    I am excited to learn Python using Raspberry Pi Zero
 This is a line appended to the file
```

让我们修改第二行，改为：`This is a line that was modified`。代码示例可与本章一起下载（`seek_to_write.py`）。

```py
if __name__ == "__main__": 
   # open text file to read and write 
   file = open('write_file.txt', 'r+') 

   # set the pointer to the desired position 
   file.seek(68) 
   file.write('that was modified \n') 

   # rewind the pointer to the beginning of the file
   file.seek(0) 
   data = file.read() 
   print(data) 
   file.close()
```

让我们回顾一下这个例子是如何工作的：

1.  这个例子的第一步是使用`r+`标志打开文件。这使得可以对文件进行读取和写入。

1.  接下来是移动到文件的第 68 个字节

1.  在这个位置将`that was modified`字符串写入文件。字符串末尾的空格用于覆盖第二句原始内容。

1.  现在，文件指针已设置到文件的开头，并读取其内容。

1.  当执行前面的代码片段时，修改后的文件内容将打印到屏幕上，如下所示：

```py
       I am excited to learn Python using Raspberry Pi Zero
 This is a line that was modified
```

还有另一个`a+`标志，它可以使数据追加到文件末尾并同时进行读取。我们将留给读者使用到目前为止讨论的示例来弄清楚这一点。

我们已经讨论了 Python 中读取和写入文件的不同示例。如果没有足够的编程经验，可能会感到不知所措。我们强烈建议通过本章提供的不同代码示例进行实际操作。

# 读者的挑战

使用`a+`标志打开`write_file.txt`文件（在不同的示例中讨论），并向文件追加一行。使用`seek`设置文件指针并打印其内容。您可以在程序中只打开文件一次。

# 使用`with`关键字

到目前为止，我们讨论了可以用于以不同模式打开文件的不同标志。我们讨论的示例遵循一个常见模式——打开文件，执行读/写操作，然后关闭文件。有一种优雅的方式可以使用`with`关键字与文件交互。

如果在与文件交互的代码块执行过程中出现任何错误，`with`关键字会确保在退出代码块时关闭文件并清理相关资源。让我们通过一个示例来回顾`with`关键字：

```py
if __name__ == "__main__": 
   with open('write_file.txt', 'r+') as file: 
         # read the contents of the file and print to the screen 
         print(file.read()) 
         file.write("This is a line appended to the file") 

         #rewind the file and read its contents 
         file.seek(0) 
         print(file.read()) 
   # the file is automatically closed at this point 
   print("Exited the with keyword code block")
```

在前面的示例（`with_keyword_example`）中，我们跳过了关闭文件，因为`with`关键字在缩进的代码块执行完毕后会自动关闭文件。`with`关键字还会在由于错误离开代码块时关闭文件。这确保了资源在任何情况下都能得到适当的清理。接下来，我们将使用`with`关键字进行文件 I/O。

# configparser

让我们讨论一些在使用树莓派开发应用程序时特别有用的 Python 编程方面。其中一个工具是 Python 中提供的`configparser`。`configparser`模块（[`docs.python.org/3.4/library/configparser.html`](https://docs.python.org/3.4/library/configparser.html)）用于读取/写入应用程序的配置文件。

在软件开发中，配置文件通常用于存储常量，如访问凭据、设备 ID 等。在树莓派的上下文中，`configparser`可以用于存储所有使用的 GPIO 引脚列表，通过 I²C 接口接口的传感器地址等。让我们讨论三个示例，学习如何使用`configparser`模块。在第一个示例中，我们将使用`configparser`创建一个`config`文件。

在第二个示例中，我们将使用`configparser`来读取配置值，在第三个示例中，我们将讨论修改配置文件的最终示例。

**示例 1**：

在第一个示例中，让我们创建一个配置文件，其中包括设备 ID、使用的 GPIO 引脚、传感器接口地址、调试开关和访问凭据等信息：

```py
import configparser 

if __name__ == "__main__": 
   # initialize ConfigParser 
   config_parser = configparser.ConfigParser() 

   # Let's create a config file 
   with open('raspi.cfg', 'w') as config_file: 
         #Let's add a section called ApplicationInfo 
         config_parser.add_section('AppInfo') 

         #let's add config information under this section 
         config_parser.set('AppInfo', 'id', '123') 
         config_parser.set('AppInfo', 'gpio', '2') 
         config_parser.set('AppInfo', 'debug_switch', 'True') 
         config_parser.set('AppInfo', 'sensor_address', '0x62') 

         #Let's add another section for credentials 
         config_parser.add_section('Credentials') 
         config_parser.set('Credentials', 'token', 'abcxyz123') 
         config_parser.write(config_file) 
   print("Config File Creation Complete")
```

让我们详细讨论前面的代码示例（可与本章一起下载作为`config_parser_write.py`）：

1.  第一步是导入`configparser`模块并创建`ConfigParser`类的实例。这个实例将被称为`config_parser`：

```py
       config_parser = configparser.ConfigParser()
```

1.  现在，我们使用`with`关键字打开名为`raspi.cfg`的配置文件。由于文件不存在，将创建一个新的配置文件。

1.  配置文件将包括两个部分，即`AppInfo`和`Credentials`。

1.  可以使用`add_section`方法创建两个部分，如下所示：

```py
       config_parser.add_section('AppInfo') 
       config_parser.add_section('Credentials')
```

1.  每个部分将包含不同的常量集。可以使用`set`方法将每个常量添加到相关部分。`set`方法的必需参数包括参数/常量将位于的部分名称，参数/常量的名称及其对应的值。例如：`id`参数可以添加到`AppInfo`部分，并分配值`123`如下：

```py
       config_parser.set('AppInfo', 'id', '123')
```

1.  最后一步是将这些配置值保存到文件中。这是使用`config_parser`方法`write`完成的。一旦程序退出`with`关键字下的缩进块，文件就会关闭：

```py
       config_parser.write(config_file)
```

我们强烈建议尝试自己尝试代码片段，并将这些片段用作参考。通过犯错误，您将学到很多，并可能得出比这里讨论的更好的解决方案。

执行上述代码片段时，将创建一个名为`raspi.cfg`的配置文件。配置文件的内容将包括以下内容所示的内容：

```py
[AppInfo] 
id = 123 
gpio = 2 
debug_switch = True 
sensor_address = 0x62 

[Credentials] 
token = abcxyz123
```

**示例 2**：

让我们讨论一个示例，我们从先前示例中创建的配置文件中读取配置参数：

```py
import configparser 

if __name__ == "__main__": 
   # initialize ConfigParser 
   config_parser = configparser.ConfigParser() 

   # Let's read the config file 
   config_parser.read('raspi.cfg') 

   # Read config variables 
   device_id = config_parser.get('AppInfo', 'id') 
   debug_switch = config_parser.get('AppInfo', 'debug_switch') 
   sensor_address = config_parser.get('AppInfo', 'sensor_address') 

   # execute the code if the debug switch is true 
   if debug_switch == "True":
         print("The device id is " + device_id) 
         print("The sensor_address is " + sensor_address)
```

如果配置文件以所示格式创建，`ConfigParser`类应该能够解析它。实际上并不一定要使用 Python 程序创建配置文件。我们只是想展示以编程方式同时为多个设备创建配置文件更容易。

上述示例可与本章一起下载（`config_parser_read.py`）。让我们讨论一下这个代码示例是如何工作的：

1.  第一步是初始化名为`config_parser`的`ConfigParser`类的实例。

1.  第二步是使用实例方法`read`加载和读取配置文件。

1.  由于我们知道配置文件的结构，让我们继续阅读位于`AppInfo`部分下可用的一些常量。可以使用`get`方法读取配置文件参数。必需的参数包括配置参数所在的部分以及参数的名称。例如：配置`id`参数位于`AppInfo`部分下。因此，该方法的必需参数包括`AppInfo`和`id`：

```py
      device_id = config_parser.get('AppInfo', 'id')
```

1.  现在配置参数已读入变量中，让我们在程序中使用它。例如：让我们测试`debug_switch`变量（用于确定程序是否处于调试模式）并打印从文件中检索到的其他配置参数：

```py
       if debug_switch == "True":
           print("The device id is " + device_id) 
           print("The sensor_address is " + sensor_address)
```

**示例 3**：

让我们讨论一个示例，我们想要修改现有的配置文件。这在需要在执行固件更新后更新配置文件中的固件版本号时特别有用。

以下代码片段可与本章一起下载，文件名为`config_parser_modify.py`：

```py
import configparser 

if __name__ == "__main__": 
   # initialize ConfigParser 
   config_parser = configparser.ConfigParser() 

   # Let's read the config file 
   config_parser.read('raspi.cfg') 

   # Set firmware version 
   config_parser.set('AppInfo', 'fw_version', 'A3') 

   # write the updated config to the config file 
   with open('raspi.cfg', 'w') as config_file: 
       config_parser.write(config_file)
```

让我们讨论一下这是如何工作的：

1.  与往常一样，第一步是初始化`ConfigParser`类的实例。使用`read`方法加载配置文件：

```py
       # initialize ConfigParser 
       config_parser = configparser.ConfigParser() 

       # Let's read the config file 
       config_parser.read('raspi.cfg')
```

1.  使用`set`方法更新必需参数（在先前的示例中讨论）：

```py
       # Set firmware version 
       config_parser.set('AppInfo', 'fw_version', 'A3')
```

1.  使用`write`方法将更新后的配置保存到配置文件中：

```py
       with open('raspi.cfg', 'w') as config_file: 
          config_parser.write(config_file)
```

# 读者的挑战

使用示例 3 作为参考，将配置参数`debug_switch`更新为值`False`。重复示例 2，看看会发生什么。

# 读取/写入 CSV 文件

在本节中，我们将讨论读取/写入 CSV 文件。这个模块（[`docs.python.org/3.4/library/csv.html`](https://docs.python.org/3.4/library/csv.html)）在数据记录应用程序中非常有用。由于我们将在下一章讨论数据记录，让我们回顾一下读取/写入 CSV 文件。

# 写入 CSV 文件

让我们考虑一个场景，我们正在从不同的传感器读取数据。这些数据需要记录到一个 CSV 文件中，其中每一列对应于来自特定传感器的读数。我们将讨论一个例子，其中我们在 CSV 文件的第一行记录值`123`、`456`和`789`，第二行将包括值`Red`、`Green`和`Blue`：

1.  写入 CSV 文件的第一步是使用`with`关键字打开 CSV 文件：

```py
       with open("csv_example.csv", 'w') as csv_file:
```

1.  下一步是初始化 CSV 模块的`writer`类的实例：

```py
       csv_writer = csv.writer(csv_file)
```

1.  现在，通过创建一个包含需要添加到行中的所有元素的列表，将每一行添加到文件中。例如：第一行可以按如下方式添加到列表中：

```py
       csv_writer.writerow([123, 456, 789])
```

1.  将所有内容放在一起，我们有：

```py
       import csv 
       if __name__ == "__main__": 
          # initialize csv writer 
          with open("csv_example.csv", 'w') as csv_file: 
                csv_writer = csv.writer(csv_file) 
                csv_writer.writerow([123, 456, 789]) 
                csv_writer.writerow(["Red", "Green", "Blue"])
```

1.  当执行上述代码片段（与本章一起提供的`csv_write.py`可下载）时，在本地目录中创建了一个 CSV 文件，其中包含以下内容：

```py
 123,456,789
 Red,Green,Blue
```

# 从 CSV 文件中读取

让我们讨论一个例子，我们读取上一节中创建的 CSV 文件的内容：

1.  读取 CSV 文件的第一步是以读模式打开它：

```py
       with open("csv_example.csv", 'r') as csv_file:
```

1.  接下来，我们初始化 CSV 模块的`reader`类的实例。CSV 文件的内容被加载到对象`csv_reader`中：

```py
       csv_reader = csv.reader(csv_file)
```

1.  现在 CSV 文件的内容已加载，可以按如下方式检索 CSV 文件的每一行：

```py
       for row in csv_reader: 
           print(row)
```

1.  将所有内容放在一起：

```py
       import csv 

       if __name__ == "__main__": 
          # initialize csv writer 
          with open("csv_example.csv", 'r') as csv_file: 
                csv_reader = csv.reader(csv_file) 

                for row in csv_reader: 
                      print(row)
```

1.  当执行上述代码片段（与本章一起提供的`csv_read.py`可下载）时，文件的内容将逐行打印，其中每一行都是一个包含逗号分隔值的列表：

```py
       ['123', '456', '789']
 ['Red', 'Green', 'Blue']
```

# Python 实用程序

Python 带有几个实用程序，可以与其他文件和操作系统本身进行交互。我们已经确定了我们在过去项目中使用过的所有这些 Python 实用程序。让我们讨论不同的模块及其用途，因为我们可能会在本书的最终项目中使用它们。

# os 模块

正如其名称所示，这个模块（[`docs.python.org/3.1/library/os.html`](https://docs.python.org/3.1/library/os.html)）可以与操作系统进行交互。让我们通过示例讨论一些应用。

# 检查文件是否存在

`os`模块可用于检查特定目录中是否存在文件。例如：我们广泛使用了`write_file.txt`文件。在打开此文件进行读取或写入之前，我们可以检查文件是否存在：

```py
import os
if __name__ == "__main__":
    # Check if file exists
    if os.path.isfile('/home/pi/Desktop/code_samples/write_file.txt'):
        print('The file exists!')
    else:
        print('The file does not exist!')
```

在上述代码片段中，我们使用了`os.path`模块中提供的`isfile()`函数。当文件位置作为函数的参数传递时，如果文件存在于该位置，则返回`True`。在这个例子中，由于文件`write_file.txt`存在于代码示例目录中，该函数返回`True`。因此屏幕上打印出消息`文件存在`：

```py
if os.path.isfile('/home/pi/Desktop/code_samples/write_file.txt'): 
    print('The file exists!') 
else: 
    print('The file does not exist!')
```

# 检查文件夹是否存在

与`os.path.isfile()`类似，还有另一个名为`os.path.isdir()`的函数。如果特定位置存在文件夹，则返回`True`。我们一直在查看位于树莓派桌面上的名为`code_samples`的文件夹中的所有代码示例。可以通过以下方式确认其存在：

```py
# Confirm code_samples' existence 
if os.path.isdir('/home/pi/Desktop/code_samples'): 
    print('The directory exists!') 
else: 
    print('The directory does not exist!')
```

# 删除文件

`os`模块还可以使用`remove()`函数删除文件。将任何文件作为函数的参数传递即可删除该文件。在*文件 I/O*部分，我们讨论了使用文本文件`read_file.txt`从文件中读取。让我们通过将其作为`remove()`函数的参数来删除该文件：

```py
os.remove('/home/pi/Desktop/code_samples/read_file.txt')
```

# 终止进程

可以通过将进程`pid`传递给`kill()`函数来终止在树莓派上运行的应用程序。在上一章中，我们讨论了在树莓派上作为后台进程运行的`light_scheduler`示例。为了演示终止进程，我们将尝试终止该进程。我们需要确定`light_scheduler`进程的进程`pid`（您可以选择由您作为用户启动的应用程序，不要触及根进程）。可以使用以下命令从命令行终端检索进程`pid`：

```py
 ps aux
```

它会显示当前在树莓派上运行的进程（如下图所示）。`light_scheduler`应用程序的进程`pid`为 1815：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d74763d0-d5d1-4183-bfba-b820bf9e0784.png)light_scheduler 守护程序的 PID

假设我们知道需要终止的应用程序的进程`pid`，让我们回顾使用`kill()`函数终止该函数。终止函数所需的参数包括进程`pid`和需要发送到进程以终止应用程序的信号（`signal.SIGKILL`）：

```py
import os
import signal
if __name__ == "__main__":
    #kill the application
    try:
        os.kill(1815, signal.SIGKILL)
    except OSError as error:
        print("OS Error " + str(error))
```

`signal`模块（[`docs.python.org/3/library/signal.html)`](https://docs.python.org/2/library/signal.html)）包含表示可用于停止应用程序的信号的常量。在此代码片段中，我们使用了`SIGKILL`信号。尝试运行`ps`命令（`ps aux`），您会注意到`light_scheduler`应用程序已被终止。

# 监控一个进程

在前面的示例中，我们讨论了使用`kill()`函数终止应用程序。您可能已经注意到，我们使用了称为`try`/`except`关键字来尝试终止应用程序。我们将在下一章详细讨论这些关键字。

还可以使用`try`/`except`关键字使用`kill()`函数来监视应用程序是否正在运行。在介绍使用`try`/`except`关键字捕获异常的概念后，我们将讨论使用`kill()`函数监视进程。

`os`模块中讨论的所有示例都可以与本章一起下载，文件名为`os_utils.py`。

# glob 模块

`glob`模块（[`docs.python.org/3/library/glob.html`](https://docs.python.org/3/library/glob.html)）使得能够识别具有特定扩展名或特定模式的文件。例如，可以列出文件夹中的所有 Python 文件如下：

```py
# List all files
for file in glob.glob('*.py'):
    print(file)
```

`glob()`函数返回一个包含`.py`扩展名的文件列表。使用`for`循环来遍历列表并打印每个文件。当执行前面的代码片段时，输出包含属于本章的所有代码示例的列表（输出被截断以表示）：

```py
read_from_file.py
config_parser_read.py
append_to_file.py
read_line_from_file.py
config_parser_modify.py
python_utils.py
config_parser_write.py
csv_write.py
```

这个模块在列出具有特定模式的文件时特别有帮助。例如：让我们考虑这样一个场景，您想要上传来自实验不同试验的文件。您只对以下格式的文件感兴趣：`file1xx.txt`，其中`x`代表`0`到`9`之间的任意数字。这些文件可以按以下方式排序和列出：

```py
# List all files of the format 1xx.txt
for file in glob.glob('txt_files/file1[0-9][0-9].txt'):
    print(file)
```

在前面的示例中，`[0-9]`表示文件名可以包含`0`到`9`之间的任意数字。由于我们正在寻找`file1xx.txt`格式的文件，因此作为参数传递给`glob()`函数的搜索模式是`file1[0-9][0-9].txt`。

当执行前面的代码片段时，输出包含指定格式的所有文本文件：

```py
txt_files/file126.txt
txt_files/file125.txt
txt_files/file124.txt
txt_files/file123.txt
txt_files/file127.txt
```

我们找到了一篇解释使用表达式对文件进行排序的文章：[`www.linuxjournal.com/content/bash-extended-globbing`](http://www.linuxjournal.com/content/bash-extended-globbing)。相同的概念可以扩展到使用`glob`模块搜索文件。

# 读者的挑战

使用`glob`模块讨论的例子可以与本章一起下载，文件名为`glob_example.py`。在其中一个例子中，我们讨论了列出特定格式的文件。你将如何列出以下格式的文件：`filexxxx.*`？（这里的`x`代表`0`到`9`之间的任意数字。`*`代表任何文件扩展名。）

# shutil 模块

`shutil`模块（[`docs.python.org/3/library/shutil.html`](https://docs.python.org/3/library/shutil.html)）使得可以使用`move()`和`copy()`方法在文件夹之间移动和复制文件。在上一节中，我们列出了文件夹`txt_files`中的所有文本文件。让我们使用`move()`将这些文件移动到当前目录（代码执行的位置），再次在`txt_files`中复制这些文件，最后从当前目录中删除这些文本文件：

```py
import glob
import shutil
import os
if __name__ == "__main__":
    # move files to the current directory
    for file in glob.glob('txt_files/file1[0-9][0-9].txt'):
        shutil.move(file, '.')
    # make a copy of files in the folder 'txt_files' and delete them
    for file in glob.glob('file1[0-9][0-9].txt'):
        shutil.copy(file, 'txt_files')
        os.remove(file)
```

在前面的例子中（可以与本章一起下载，文件名为`shutil_example.py`），文件被移动和复制，源和目的地分别作为第一个和第二个参数指定。

使用`glob`模块识别要移动（或复制）的文件，然后使用它们对应的方法移动或复制每个文件。

# subprocess 模块

我们在上一章简要讨论了这个模块。`subprocess`模块（[`docs.python.org/3.2/library/subprocess.html`](https://docs.python.org/3.2/library/subprocess.html)）使得可以在 Python 程序内部启动另一个程序。`subprocess`模块中常用的函数之一是`Popen`。需要在程序内部启动的任何进程都需要作为列表参数传递给`Popen`函数：

```py
import subprocess
if __name__ == "__main__":
    subprocess.Popen(['aplay', 'tone.wav'])
```

在前面的例子中，`tone.wav`（需要播放的 WAVE 文件）和需要运行的命令作为列表参数传递给函数。`subprocess`模块中还有其他几个类似用途的命令。我们留给你去探索。

# sys 模块

`sys`模块（[`docs.python.org/3/library/sys.html`](https://docs.python.org/3/library/sys.html)）允许与 Python 运行时解释器进行交互。`sys`模块的一个功能是解析作为程序输入提供的命令行参数。让我们编写一个程序，读取并打印作为程序参数传递的文件的内容：

```py
import sys
if __name__ == "__main__":
    with open(sys.argv[1], 'r') as read_file:
        print(read_file.read())
```

尝试按以下方式运行前面的例子：

```py
python3 sys_example.py read_lines.txt
```

前面的例子可以与本章一起下载，文件名为`sys_example.py`。在运行程序时传递的命令行参数列表可以在`sys`模块的`argv`列表中找到。`argv[0]`通常是 Python 程序的名称，`argv[1]`通常是传递给函数的第一个参数。

当以`read_lines.txt`作为参数执行`sys_example.py`时，程序应该打印文本文件的内容：

```py
I am learning Python Programming using the Raspberry Pi Zero.
This is the second line.
Line 3.
Line 4.
Line 5.
Line 6.
Line 7.
```

# 总结

在本章中，我们讨论了文件 I/O - 读取和写入文件，以及用于读取、写入和追加文件的不同标志。我们谈到了将文件指针移动到文件的不同位置以检索特定内容或在特定位置覆盖文件内容。我们讨论了 Python 中的`ConfigParser`模块及其在存储/检索应用程序配置参数以及读写 CSV 文件中的应用。

最后，我们讨论了在我们的项目中潜在使用的不同 Python 工具。我们将广泛使用文件 I/O 和在本书中讨论的 Python 工具。我们强烈建议在进入本书中讨论的最终项目之前，熟悉本章讨论的概念。

在接下来的章节中，我们将讨论将存储在 CSV 文件中的传感器数据上传到云端，以及记录应用程序执行过程中遇到的错误。下一章见！


# 第十五章：请求和 Web 框架

本章的主要内容是 Python 中的请求和 Web 框架。我们将讨论使得从 Web 检索数据（例如，获取天气更新）、将数据上传到远程服务器（例如，记录传感器数据）或控制本地网络上的设备成为可能的库和框架。我们还将讨论一些有助于学习本章核心主题的话题。

# `try`/`except`关键字

到目前为止，我们已经审查并测试了所有的例子，假设程序的执行不会遇到错误。相反，应用程序有时会由于外部因素（如无效的用户输入和糟糕的互联网连接）或程序员造成的程序逻辑错误而失败。在这种情况下，我们希望程序报告/记录错误的性质，并在退出程序之前继续执行或清理资源。`try`/`except`关键字提供了一种机制，可以捕获程序执行过程中发生的错误并采取补救措施。由于可能在代码的关键部分捕获和记录错误，`try`/`except`关键字在调试应用程序时特别有用。

通过比较两个例子来理解`try`/`except`关键字。让我们构建一个简单的猜数字游戏，用户被要求猜一个 0 到 9 之间的数字：

1.  使用 Python 的`random`模块生成一个随机数（在 0 到 9 之间）。如果用户猜测的数字正确，Python 程序会宣布用户为赢家并退出游戏。

1.  如果用户输入是字母`x`，程序会退出游戏。

1.  用户输入使用`int()`函数转换为整数。进行了一个合理性检查，以确定用户输入是否是 0 到 9 之间的数字。

1.  整数与随机数进行比较。如果它们相同，程序会宣布用户为赢家并退出游戏。

让我们观察当我们故意向这个程序提供错误的输入时会发生什么（这里显示的代码片段可以在本章的下载中找到，文件名为`guessing_game.py`）：

```py
import random

if __name__ == "__main__":
    while True:
        # generate a random number between 0 and 9
        rand_num = random.randrange(0,10)

        # prompt the user for a number
        value = input("Enter a number between 0 and 9: ")

        if value == 'x':
            print("Thanks for playing! Bye!")
            break

        input_value = int(value)

        if input_value < 0 or input_value > 9:
            print("Input invalid. Enter a number between 0 and 9.")

        if input_value == rand_num:
            print("Your guess is correct! You win!")
            break
        else:
            print("Nope! The random value was %s" % rand_num)
```

让我们执行前面的代码片段，并向程序提供输入`hello`：

```py
    Enter a number between 0 and 9: hello
 Traceback (most recent call last):
 File "guessing_game.py", line 12, in <module>
 input_value = int(value)
 ValueError: invalid literal for int() with base 10: 'hello'
```

在前面的例子中，当程序试图将用户输入`hello`转换为整数时失败。程序执行以异常结束。异常突出了发生错误的行。在这种情况下，它发生在第 10 行：

```py
    File "guessing_game.py", line 12, in <module>
 input_value = int(value)
```

异常的性质也在异常中得到了突出。在这个例子中，最后一行表明抛出的异常是`ValueError`：

```py
    ValueError: invalid literal for int() with base 10: 'hello'
```

让我们讨论一个相同的例子（可以在本章的下载中找到，文件名为`try_and_except.py`），它使用了`try`/`except`关键字。在捕获异常并将其打印到屏幕后，可以继续玩游戏。我们有以下代码：

```py
import random

if __name__ == "__main__":
    while True:
        # generate a random number between 0 and 9
        rand_num = random.randrange(0,10)

        # prompt the user for a number
        value = input("Enter a number between 0 and 9: ")

        if value == 'x':
            print("Thanks for playing! Bye!")

        try:
            input_value = int(value)
        except ValueError as error:
            print("The value is invalid %s" % error)
            continue

        if input_value < 0 or input_value > 9:
            print("Input invalid. Enter a number between 0 and 9.")
            continue

        if input_value == rand_num:
            print("Your guess is correct! You win!")
            break
        else:
            print("Nope! The random value was %s" % rand_num)
```

让我们讨论相同的例子如何使用`try`/`except`关键字：

1.  从前面的例子中，我们知道当用户提供错误的输入时（例如，一个字母而不是 0 到 9 之间的数字），异常发生在第 10 行（用户输入转换为整数的地方），错误的性质被命名为`ValueError`。

1.  可以通过将其包装在`try...except`块中来避免程序执行的中断：

```py
      try: 
         input_value = int(value) 
      except ValueError as error:
         print("The value is invalid %s" % error)
```

1.  在接收到用户输入时，程序会在`try`块下尝试将用户输入转换为整数。

1.  如果发生了`ValueError`，`except`块会捕获`error`，并将以下消息与实际错误消息一起打印到屏幕上：

```py
       except ValueError as error:
           print("The value is invalid %s" % error)
```

1.  尝试执行代码示例并提供无效输入。您会注意到程序打印了错误消息（以及错误的性质），然后返回游戏循环的顶部并继续寻找有效的用户输入：

```py
       Enter a number between 0 and 9: 3
 Nope! The random value was 5
 Enter a number between 0 and 9: hello
 The value is invalid invalid literal for int() with
       base 10: 'hello'
 Enter a number between 0 and 10: 4
 Nope! The random value was 6
```

`try...except`块带来了相当大的处理成本。因此，将`try...except`块保持尽可能短是很重要的。因为我们知道错误发生在尝试将用户输入转换为整数的行上，所以我们将其包装在`try...except`块中以捕获错误。

因此，`try`/`except`关键字用于防止程序执行中的任何异常行为，因为出现错误。它使得能够记录错误并采取补救措施。与`try...except`块类似，还有`try...except...else`和`try...except...else`代码块。让我们通过几个例子快速回顾一下这些选项。

# try...except...else

`try...except...else`块在我们希望只有在没有引发异常时才执行特定代码块时特别有用。为了演示这个概念，让我们使用这个块来重写猜数字游戏示例：

```py
try:
    input_value = int(value)
except ValueError as error:
    print("The value is invalid %s" % error)
else:
    if input_value < 0 or input_value > 9:
        print("Input invalid. Enter a number between 0 and 9.")
    elif input_value == rand_num:
        print("Your guess is correct! You win!")
        break
    else:
        print("Nope! The random value was %s" % rand_num)
```

使用`try...except...else`块修改的猜数字游戏示例可与本章一起下载，文件名为`try_except_else.py`。在这个例子中，程序仅在接收到有效的用户输入时才将用户输入与随机数进行比较。否则，它会跳过`else`块并返回到循环顶部以接受下一个用户输入。因此，当`try`块中的代码没有引发异常时，`try...except...else`被用来执行特定的代码块。

# try...except...else...finally

正如其名称所示，`finally`块用于在离开`try`块时执行一块代码。即使在引发异常后，这段代码也会被执行。这在我们需要在进入下一个阶段之前清理资源和释放内存时非常有用。

让我们使用我们的猜数字游戏来演示`finally`块的功能。为了理解`finally`关键字的工作原理，让我们使用一个名为`count`的计数器变量，在`finally`块中递增，以及另一个名为`valid_count`的计数器变量，在`else`块中递增。我们有以下代码：

```py
count = 0
valid_count = 0
while True:
  # generate a random number between 0 and 9
  rand_num = random.randrange(0,10)

  # prompt the user for a number
  value = input("Enter a number between 0 and 9: ")

  if value == 'x':
      print("Thanks for playing! Bye!")

  try:
      input_value = int(value)
  except ValueError as error:
      print("The value is invalid %s" % error)
  else:
      if input_value < 0 or input_value > 9:
          print("Input invalid. Enter a number between 0 and 9.")
          continue

      valid_count += 1
      if input_value == rand_num:
          print("Your guess is correct! You win!")
          break
      else:
          print("Nope! The random value was %s" % rand_num)
  finally:
      count += 1

print("You won the game in %d attempts "\
      "and %d inputs were valid" % (count, valid_count))
```

上述代码片段来自`try_except_else_finally.py`代码示例（可与本章一起下载）。尝试执行代码示例并玩游戏。您将注意到赢得游戏所需的总尝试次数以及有效输入的数量：

```py
    Enter a number between 0 and 9: g
 The value is invalid invalid literal for int() with
    base 10: 'g'
 Enter a number between 0 and 9: 3
 Your guess is correct! You win!
 You won the game in 9 attempts and 8 inputs were valid
```

这演示了`try-except-else-finally`块的工作原理。当关键代码块（在`try`关键字下）成功执行时，`else`关键字下的任何代码都会被执行，而在退出`try...except`块时（在退出代码块时清理资源时）`finally`关键字下的代码块会被执行。

使用先前的代码示例玩游戏时提供无效的输入，以了解代码块流程。

# 连接到互联网 - 网络请求

现在我们已经讨论了`try`/`except`关键字，让我们利用它来构建一个连接到互联网的简单应用程序。我们将编写一个简单的应用程序，从互联网上获取当前时间。我们将使用 Python 的`requests`库（[`requests.readthedocs.io/en/master/#`](http://requests.readthedocs.io/en/master/#)）。

`requests`模块使得连接到网络和检索信息成为可能。为了做到这一点，我们需要使用`requests`模块中的`get()`方法来发出请求：

```py
import requests
response = requests.get('http://nist.time.gov/actualtime.cgi')
```

在上述代码片段中，我们将一个 URL 作为参数传递给`get()`方法。在这种情况下，它是返回当前时间的 Unix 格式的 URL（[`en.wikipedia.org/wiki/Unix_time`](https://en.wikipedia.org/wiki/Unix_time)）。

让我们利用`try`/`except`关键字来请求获取当前时间：

```py
#!/usr/bin/python3

import requests

if __name__ == "__main__":
  # Source for link: http://stackoverflow.com/a/30635751/822170
  try:
    response = requests.get('http://nist.time.gov/actualtime.cgi')
    print(response.text)
  except requests.exceptions.ConnectionError as error:
    print("Something went wrong. Try again")
```

在前面的例子中（可以与本章一起下载，命名为`internet_access.py`），请求是在`try`块下进行的，响应（由`response.text`返回）被打印到屏幕上。

如果在执行请求以检索当前时间时出现错误，将引发`ConnectionError`（[`requests.readthedocs.io/en/master/user/quickstart/#errors-and-exceptions`](http://requests.readthedocs.io/en/master/user/quickstart/#errors-and-exceptions)）。这个错误可能是由于缺乏互联网连接或不正确的 URL 引起的。这个错误被`except`块捕获。尝试运行这个例子，它应该返回`time.gov`的当前时间：

```py
    <timestamp time="1474421525322329" delay="0"/>
```

# requests 的应用-检索天气信息

让我们使用`requests`模块来检索旧金山市的天气信息。我们将使用**OpenWeatherMap** API ([openweathermap.org](http://openweathermap.org))来检索天气信息：

1.  为了使用 API，注册一个 API 账户并获取一个 API 密钥（免费）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e491b6d7-eedd-4706-a6c2-7ffe0ae779fb.png)来自 openweathermap.org 的 API 密钥

1.  根据 API 文档（[openweathermap.org/current](http://openweathermap.org/current)），可以使用`http://api.openweathermap.org/data/2.5/weather?zip=SanFrancisco&appid=API_KEY&units=imperial`作为 URL 来检索一个城市的天气信息。

1.  用你的账户的密钥替换`API_KEY`，并在浏览器中使用它来检索当前的天气信息。你应该能够以以下格式检索到天气信息：

```py
 {"coord":{"lon":-122.42,"lat":37.77},"weather":[{"id":800, 
       "main":"Clear","description":"clear sky","icon":"01n"}],"base": 
       "stations","main":{"temp":71.82,"pressure":1011,"humidity":50, 
       "temp_min":68,"temp_max":75.99},"wind":
       {"speed":13.04,"deg":291},
       "clouds":{"all":0},"dt":1474505391,"sys":{"type":3,"id":9966, 
       "message":0.0143,"country":"US","sunrise":1474552682, 
       "sunset":1474596336},"id":5391959,"name":"San 
       Francisco","cod":200}
```

天气信息（如前所示）以 JSON 格式返回。**JavaScript 对象表示法**（**JSON**）是一种广泛用于在网络上传递数据的数据格式。JSON 格式的主要优点是它是一种可读的格式，许多流行的编程语言支持将数据封装在 JSON 格式中。如前面的片段所示，JSON 格式使得以可读的名称/值对交换信息成为可能。

让我们回顾一下使用`requests`模块检索天气并解析 JSON 数据：

1.  用前面例子中的 URL（`internet_access.py`）替换为本例中讨论的 URL。这应该以 JSON 格式返回天气信息。

1.  requests 模块提供了一个解析 JSON 数据的方法。响应可以按以下方式解析：

```py
       response = requests.get(URL) 
       json_data = response.json()
```

1.  `json()`函数解析来自 OpenWeatherMap API 的响应，并返回不同天气参数（`json_data`）及其值的字典。

1.  由于我们知道 API 文档中的响应格式，可以从解析后的响应中检索当前温度：

```py
       print(json_data['main']['temp'])
```

1.  把所有这些放在一起，我们有这个：

```py
       #!/usr/bin/python3

       import requests

       # generate your own API key
       APP_ID = '5d6f02fd4472611a20f4ce602010ee0c'
       ZIP = 94103
       URL = """http://api.openweathermap.org/data/2.5/weather?zip={}
       &appid={}&units=imperial""".format(ZIP, APP_ID)

       if __name__ == "__main__":
         # API Documentation: http://openweathermap.org/
         current#current_JSON
         try:
           # encode data payload and post it
           response = requests.get(URL)
           json_data = response.json()
           print("Temperature is %s degrees Fahrenheit" %
           json_data['main']['temp'])
         except requests.exceptions.ConnectionError as error:
           print("The error is %s" % error)
```

前面的例子可以与本章一起下载，命名为`weather_example.py`。该例子应该显示当前的温度如下：

```py
    Temperature is 68.79 degrees Fahrenheit
```

# requests 的应用-将事件发布到互联网

在上一个例子中，我们从互联网上检索了信息。让我们考虑一个例子，在这个例子中，我们需要在互联网上发布传感器事件。这可能是你不在家时猫门打开，或者有人踩在你家门口的地垫上。因为我们在上一章中讨论了如何将传感器与树莓派 Zero 连接，所以让我们讨论一个场景，我们可以将这些事件发布到*Slack*——一个工作场所通讯工具，Twitter，或者云服务，比如**Phant** ([`data.sparkfun.com/`](https://data.sparkfun.com/))。

在这个例子中，我们将使用`requests`将这些事件发布到 Slack。每当发生传感器事件，比如猫门打开时，让我们在 Slack 上给自己发送直接消息。我们需要一个 URL 来将这些传感器事件发布到 Slack。让我们回顾一下生成 URL 以将传感器事件发布到 Slack：

1.  生成 URL 的第一步是创建一个*incoming webhook*。Webhook 是一种可以将消息作为有效负载发布到应用程序（如 Slack）的请求类型。

1.  如果您是名为*TeamX*的 Slack 团队成员，请在浏览器中启动您团队的应用程序目录，即`teamx.slack.com/apps`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/dea1e47a-e8f1-4848-b40e-1cdd2836fcbc.png)启动您团队的应用程序目录

1.  在应用程序目录中搜索`incoming webhooks`，并选择第一个选项，Incoming WebHooks（如下截图所示）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/bb557455-62ba-4716-8699-695bbf6be867.png)选择 incoming webhooks

1.  点击添加配置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/2b0b1d70-c3f9-4f41-bbfb-ea0b0ed6c3a8.png)添加配置

1.  当事件发生时，让我们向自己发送私人消息。选择 Privately to (you)作为选项，并通过单击添加 Incoming WebHooks 集成来创建一个 webhook：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e37bc0b4-1cce-4840-9313-f2bfe7d0b60e.png)选择 Privately to you

1.  我们已经生成了一个 URL，用于发送有关传感器事件的直接消息（URL 部分隐藏）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/21db2e44-ca8f-4a25-acd3-355752853efa.png)生成的 URL

1.  现在，我们可以使用先前提到的 URL 在 Slack 上向自己发送直接消息。传感器事件可以作为 JSON 有效负载发布到 Slack。让我们回顾一下如何将传感器事件发布到 Slack。

1.  例如，让我们考虑在猫门打开时发布消息。第一步是为消息准备 JSON 有效负载。根据 Slack API 文档（[`api.slack.com/custom-integrations)`](https://api.slack.com/custom-integrations)），消息有效负载需要采用以下格式：

```py
       payload = {"text": "The cat door was just opened!"}
```

1.  为了发布此事件，我们将使用`requests`模块中的`post()`方法。在发布时，数据有效负载需要以 JSON 格式进行编码：

```py
       response = requests.post(URL, json.dumps(payload))
```

1.  将所有内容放在一起，我们有：

```py
       #!/usr/bin/python3

       import requests
       import json

       # generate your own URL
       URL = 'https://hooks.slack.com/services/'

       if __name__ == "__main__":
         payload = {"text": "The cat door was just opened!"}
         try:
           # encode data payload and post it
           response = requests.post(URL, json.dumps(payload))
           print(response.text)
         except requests.exceptions.ConnectionError as error:
           print("The error is %s" % error)
```

1.  在发布消息后，请求返回`ok`作为响应。这表明发布成功了。

1.  生成您自己的 URL 并执行上述示例（与本章一起提供的`slack_post.py`一起下载）。您将在 Slack 上收到直接消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b593e295-094d-403e-a245-a79068060b26.png)在 Slack 上直接发送消息

现在，尝试将传感器接口到 Raspberry Pi Zero（在前几章中讨论），并将传感器事件发布到 Slack。

还可以将传感器事件发布到 Twitter，并让您的 Raspberry Pi Zero 检查新邮件等。查看本书的网站以获取更多示例。

# Flask web 框架

在我们的最后一节中，我们将讨论 Python 中的 Web 框架。我们将讨论 Flask 框架（[`flask.pocoo.org/`](http://flask.pocoo.org/)）。基于 Python 的框架使得可以使用 Raspberry Pi Zero 将传感器接口到网络。这使得可以在网络中的任何位置控制设备并从传感器中读取数据。让我们开始吧！

# 安装 Flask

第一步是安装 Flask 框架。可以按以下方式完成：

```py
    sudo pip3 install flask
```

# 构建我们的第一个示例

Flask 框架文档解释了构建第一个示例。根据文档修改示例如下：

```py
#!/usr/bin/python3

from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!"

if __name__ == "__main__":
    app.run('0.0.0.0')
```

启动此示例（与本章一起提供的`flask_example.py`一起下载），它应该在 Raspberry Pi Zero 上启动一个对网络可见的服务器。在另一台计算机上，启动浏览器，并输入 Raspberry Pi Zero 的 IP 地址以及端口号`5000`作为后缀（如下快照所示）。它应该将您带到服务器的索引页面，显示消息 Hello World!：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/c515611e-7de9-40cc-a867-0fbc6cd43c88.png)基于 Flask 框架的 Raspberry Pi Zero 上的 Web 服务器

您可以使用命令行终端上的`ifconfig`命令找到 Raspberry Pi Zero 的 IP 地址。

# 使用 Flask 框架控制设备

让我们尝试使用 Flask 框架在家中打开/关闭电器。在之前的章节中，我们使用*PowerSwitch Tail II*来控制树莓派 Zero 上的台灯。让我们尝试使用 Flask 框架来控制相同的东西。按照以下图示连接 PowerSwitch Tail：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/587aacf5-ad6d-45f6-bc42-214248b72183.png)使用 Flask 框架控制台灯

根据 Flask 框架文档，可以将 URL 路由到特定函数。例如，可以使用`route()`将`/lamp/<control>`绑定到`control()`函数：

```py
@app.route("/lamp/<control>") 
def control(control): 
  if control == "on": 
    lights.on() 
  elif control == "off": 
    lights.off() 
  return "Table lamp is now %s" % control
```

在前面的代码片段中，`<control>`是一个可以作为参数传递给绑定函数的变量。这使我们能够打开/关闭灯。例如，`<IP 地址>:5000/lamp/on`打开灯，反之亦然。把它们放在一起，我们有这样：

```py
#!/usr/bin/python3 

from flask import Flask 
from gpiozero import OutputDevice 

app = Flask(__name__) 
lights = OutputDevice(2) 

@app.route("/lamp/<control>") 
def control(control): 
  if control == "on": 
    lights.on() 
  elif control == "off": 
    lights.off() 
  return "Table lamp is now %s" % control 

if __name__ == "__main__": 
    app.run('0.0.0.0')
```

上述示例可与本章一起下载，文件名为`appliance_control.py`。启动基于 Flask 的 Web 服务器，并在另一台计算机上打开 Web 服务器。为了打开灯，输入`<树莓派 Zero 的 IP 地址>:5000/lamp/on`作为 URL：

这应该打开灯：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/06292c52-263d-41b8-bf2c-9cb2503a77dd.png)

因此，我们建立了一个简单的框架，可以控制网络中的电器。可以在 HTML 页面中包含按钮，并将它们路由到特定的 URL 以执行特定的功能。Python 中还有几个其他框架可以开发 Web 应用程序。我们只是向您介绍了 Python 可能的不同应用程序。我们建议您查看本书的网站，了解更多示例，例如使用 Flask 框架控制万圣节装饰和其他节日装饰。

# 摘要

在本章中，我们讨论了 Python 中的`try`/`except`关键字。我们还讨论了从互联网检索信息的应用程序，以及将传感器事件发布到互联网。我们还讨论了 Python 的 Flask Web 框架，并演示了在网络中控制电器。在下一章中，我们将讨论 Python 中的一些高级主题。


# 第十六章：使用 Python 可以开发的一些很棒的东西

在本章中，我们将讨论 Python 中的一些高级主题。我们还将讨论一些独特的主题（如图像处理），让您开始使用 Python 进行应用程序开发。

# 使用 Raspberry Pi Zero 进行图像处理

Raspberry Pi Zero 是一款价格便宜的硬件，配备了 1 GHz 处理器。虽然它不足以运行某些高级图像处理操作，但可以帮助您在 25 美元的预算内学习基础知识（Raspberry Pi Zero 和摄像头的成本）。

我们建议您在 Raspberry Pi Zero 上使用 16 GB（或更高）的卡来安装本节讨论的图像处理工具集。

例如，您可以使用 Raspberry Pi Zero 来跟踪后院的鸟。在本章中，我们将讨论在 Raspberry Pi Zero 上开始图像处理的不同方法。

为了在本节中使用摄像头测试一些示例，需要 Raspberry Pi Zero v1.3 或更高版本。检查您的 Raspberry Pi Zero 的背面以验证板的版本：

识别您的 Raspberry Pi Zero 的版本

# OpenCV

**OpenCV**是一个开源工具箱，包括为图像处理开发的不同软件工具。OpenCV 是一个跨平台的工具箱，支持不同的操作系统。由于 OpenCV 在开源许可下可用，全世界的研究人员通过开发工具和技术为其增长做出了贡献。这使得开发应用程序相对容易。OpenCV 的一些应用包括人脸识别和车牌识别。

由于其有限的处理能力，安装框架可能需要几个小时。在我们这里大约花了 10 个小时。

我们按照[`www.pyimagesearch.com/2015/10/26/how-to-install-opencv-3-on-raspbian-jessie/`](http://www.pyimagesearch.com/2015/10/26/how-to-install-opencv-3-on-raspbian-jessie/)上的指示在 Raspberry Pi Zero 上安装 OpenCV。我们特别按照了使用 Python 3.x 绑定安装 OpenCV 的指示，并验证了安装过程。我们大约花了 10 个小时来完成在 Raspberry Pi Zero 上安装 OpenCV。出于不重复造轮子的考虑，我们不会重复这些指示。

# 安装的验证

让我们确保 OpenCV 安装及其 Python 绑定工作正常。启动命令行终端，并确保您已经通过执行`workon cv`命令启动了`cv`虚拟环境（您可以验证您是否在`cv`虚拟环境中）：

验证您是否在 cv 虚拟环境中

现在，让我们确保我们的安装工作正常。从命令行启动 Python 解释器，并尝试导入`cv2`模块：

```py
    >>> import cv2
 >>> cv2.__version__
 '3.0.0'
```

这证明了 OpenCV 已经安装在 Raspberry Pi Zero 上。让我们编写一个涉及 OpenCV 的*hello world*示例。在这个示例中，我们将打开一张图像（这可以是您的 Raspberry Pi Zero 桌面上的任何彩色图像），并在将其转换为灰度后显示它。我们将使用以下文档来编写我们的第一个示例：[`docs.opencv.org/3.0-beta/doc/py_tutorials/py_gui/py_image_display/py_image_display.html`](http://docs.opencv.org/3.0-beta/doc/py_tutorials/py_gui/py_image_display/py_image_display.html)。

根据文档，我们需要使用`imread()`函数来读取图像文件的内容。我们还需要指定要读取图像的格式。在这种情况下，我们将以灰度格式读取图像。这由作为函数的第二个参数传递的`cv2.IMREAD_GRAYSCALE`来指定：

```py
import cv2 

img = cv2.imread('/home/pi/screenshot.jpg',cv2.IMREAD_GRAYSCALE)
```

现在图像以灰度格式加载并保存到`img`变量中，我们需要在新窗口中显示它。这是通过`imshow()`函数实现的。根据文档，我们可以通过将窗口名称指定为第一个参数，将图像指定为第二个参数来显示图像：

```py
cv2.imshow('image',img)
```

在这种情况下，我们将打开一个名为`image`的窗口，并显示我们在上一步加载的`img`的内容。我们将显示图像，直到收到按键。这是通过使用`cv2.waitKey()`函数实现的。根据文档，`waitkey()`函数监听键盘事件：

```py
cv2.waitKey(0)
```

`0`参数表示我们将无限期等待按键。根据文档，当以毫秒为单位的持续时间作为参数传递时，`waitkey()`函数会监听指定持续时间的按键。当按下任何键时，窗口会被`destroyAllWindows()`函数关闭：

```py
cv2.destroyAllWindows()
```

将所有部件组装在一起，我们有：

```py
import cv2

img = cv2.imread('/home/pi/screenshot.jpg',cv2.IMREAD_GRAYSCALE)
cv2.imshow('image',img)
cv2.waitKey(0)
cv2.destroyAllWindows()
```

上述代码示例可在本章的`opencv_test.py`中下载。安装 OpenCV 库后，尝试加载图像，如本示例所示。它应该以灰度加载图像，如下图所示：

树莓派桌面以灰度加载

这个窗口会在按下任意键时关闭。

# 向读者提出挑战

在上面的示例中，窗口在按下任意键时关闭。查看文档，确定是否可能在按下鼠标按钮时关闭所有窗口。

# 将相机安装到树莓派 Zero

测试我们下一个示例需要相机连接器和相机。购买相机和适配器的一个来源如下：

| **名称** | **来源** |
| --- | --- |
| 树莓派 Zero 相机适配器 | [`thepihut.com/products/raspberry-pi-zero-camera-adapter`](https://thepihut.com/products/raspberry-pi-zero-camera-adapter) |
| 树莓派相机 | [`thepihut.com/products/raspberry-pi-camera-module`](https://thepihut.com/products/raspberry-pi-camera-module) |

执行以下步骤将相机安装到树莓派 Zero 上：

1.  第一步是将相机连接到树莓派 Zero。相机适配器可以安装如下图所示。抬起连接器标签，滑动相机适配器并轻轻按下连接器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ce975b8d-7043-48b9-888c-5cc2f83c2bbc.jpg)

1.  我们需要在树莓派 Zero 上启用相机接口。在桌面上，转到首选项并启动树莓派配置。在树莓派配置的接口选项卡下，启用相机，并保存配置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f4cb1bc3-eb01-4a84-93d0-ab51a26c6525.png)启用相机接口

1.  通过从命令行终端运行以下命令来拍照测试相机：

```py
       raspistill -o /home/pi/Desktop/test.jpg
```

1.  它应该拍照并保存到树莓派桌面上。验证相机是否正常工作。如果无法使相机工作，我们建议查看树莓派基金会发布的故障排除指南：[`www.raspberrypi.org/documentation/raspbian/applications/camera.md`](https://www.raspberrypi.org/documentation/raspbian/applications/camera.md)。

相机电缆有点笨重，拍照时可能会有些困难。我们建议使用相机支架。我们发现这个很有用（如下图所示）[`a.co/hQolR7O`](http://a.co/hQolR7O)：

使用树莓派相机的支架

让我们试试相机，并与 OpenCV 库一起使用：

1.  我们将使用相机拍照，并使用 OpenCV 框架显示它。为了在 Python 中访问相机，我们需要`picamera`包。可以按照以下方式安装：

```py
       pip3 install picamera
```

1.  让我们确保包能够按预期使用一个简单的程序。`picamera`包的文档可在[`picamera.readthedocs.io/en/release-1.12/api_camera.html`](https://picamera.readthedocs.io/en/release-1.12/api_camera.html)找到。

1.  第一步是初始化`PiCamera`类。接下来是翻转图像，使其在垂直轴上翻转。这仅在相机倒置安装时才需要。在其他安装中可能不需要：

```py
       with PiCamera() as camera: 
       camera.vflip = True
```

1.  在拍照之前，我们可以使用`start_preview()`方法预览即将捕获的图片：

```py
       camera.start_preview()
```

1.  在我们拍照之前，让我们预览`10`秒钟。我们可以使用`capture()`方法拍照：

```py
       sleep(10) 
       camera.capture("/home/pi/Desktop/desktop_shot.jpg") 
       camera.stop_preview()
```

1.  `capture()`方法需要文件位置作为参数（如前面的代码片段所示）。完成后，我们可以使用`stop_preview()`关闭相机预览。

1.  总结一下，我们有：

```py
       from picamera import PiCamera 
       from time import sleep

       if __name__ == "__main__": 
         with PiCamera() as camera: 
           camera.vflip = True 
           camera.start_preview() 
           sleep(10) 
           camera.capture("/home/pi/Desktop/desktop_shot.jpg") 
           camera.stop_preview()
```

上述代码示例可与本章一起下载，文件名为`picamera_test.py`。使用相机拍摄的快照如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/355f9dc6-2b49-4a4a-82df-4dc5cb381f71.png)使用树莓派摄像头模块捕获的图像

1.  让我们将此示例与上一个示例结合起来——将此图像转换为灰度并显示，直到按下键。确保您仍然在`cv`虚拟环境工作空间中。

1.  让我们将捕获的图像转换为灰度，如下所示：

```py
       img = cv2.imread("/home/pi/Desktop/desktop_shot.jpg",
       cv2.IMREAD_GRAYSCALE)
```

以下是捕获后转换的图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/48620f3f-ce1a-4271-8e97-d07f43502fbf.png)图像在捕获时转换为灰度

1.  现在我们可以按如下方式显示灰度图像：

```py
       cv2.imshow("image", img) 
       cv2.waitKey(0) 
       cv2.destroyAllWindows()
```

修改后的示例可作为`picamera_opencvtest.py`进行下载。

到目前为止，我们已经展示了在 Python 中开发图像处理应用程序。我们还建议查看 OpenCV Python 绑定文档中提供的示例（在本节介绍部分提供了链接）。

# 语音识别

在本节中，我们将讨论在 Python 中开发语音识别示例涉及语音识别。我们将利用`requests`模块（在上一章中讨论）来使用`wit.ai`（[`wit.ai/`](https://wit.ai/)）转录音频。

有几种语音识别工具，包括 Google 的语音 API、IBM Watson、Microsoft Bing 的语音识别 API。我们以`wit.ai`为例进行演示。

语音识别在我们希望使树莓派零对语音命令做出响应的应用中非常有用。

让我们回顾使用`wit.ai`在 Python 中构建语音识别应用程序（其文档可在[`github.com/wit-ai/pywit`](https://github.com/wit-ai/pywit)找到）。为了进行语音识别和识别语音命令，我们需要一个麦克风。但是，我们将演示使用一个现成的音频样本。我们将使用一篇研究出版物提供的音频样本（可在[`ecs.utdallas.edu/loizou/speech/noizeus/clean.zip`](http://ecs.utdallas.edu/loizou/speech/noizeus/clean.zip)找到）。

`wit.ai` API 许可证规定，该工具可免费使用，但上传到其服务器的音频用于调整其语音转录工具。

我们现在将尝试转录`sp02.wav`音频样本，执行以下步骤：

1.  第一步是注册`wit.ai`帐户。请注意以下截图中显示的 API：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f4e59c40-82a5-4fcf-8ccc-d7512b47c0fe.png)

1.  第一步是安装 requests 库。可以按以下方式安装：

```py
       pip3 install requests 
```

1.  根据`wit.ai`的文档，我们需要向我们的请求添加自定义标头，其中包括 API 密钥（用您的帐户中的令牌替换`$TOKEN`）。我们还需要在标头中指定文件格式。在这种情况下，它是一个`.wav`文件，采样频率为 8000 Hz：

```py
       import requests 

       if __name__ == "__main__": 
         url = 'https://api.wit.ai/speech?v=20161002' 
         headers = {"Authorization": "Bearer $TOKEN", 
                    "Content-Type": "audio/wav"}
```

1.  为了转录音频样本，我们需要将音频样本附加到请求体中：

```py
       files = open('sp02.wav', 'rb') 
       response = requests.post(url, headers=headers, data=files) 
       print(response.status_code) 
       print(response.text)
```

1.  将所有这些放在一起，我们得到了这个：

```py
       #!/usr/bin/python3 

       import requests 

       if __name__ == "__main__": 
         url = 'https://api.wit.ai/speech?v=20161002' 
         headers = {"Authorization": "Bearer $TOKEN", 
                    "Content-Type": "audio/wav"} 
         files = open('sp02.wav', 'rb') 
         response = requests.post(url, headers=headers, data=files) 
         print(response.status_code) 
         print(response.text)
```

前面的代码示例可与本章一起下载，文件名为`wit_ai.py`。尝试执行前面的代码示例，它应该会转录音频样本：`sp02.wav`。我们有以下代码：

```py
200
{
  "msg_id" : "fae9cc3a-f7ed-4831-87ba-6a08e95f515b",
  "_text" : "he knew the the great young actress",
  "outcomes" : [ {
    "_text" : "he knew the the great young actress",
    "confidence" : 0.678,
    "intent" : "DataQuery",
    "entities" : {
      "value" : [ {
        "confidence" : 0.7145905790744499,
        "type" : "value",
        "value" : "he",
        "suggested" : true
      }, {
        "confidence" : 0.5699616515542044,
        "type" : "value",
        "value" : "the",
        "suggested" : true
      }, {
        "confidence" : 0.5981701138805214,
        "type" : "value",
        "value" : "great",
        "suggested" : true
      }, {
        "confidence" : 0.8999612482250062,
        "type" : "value",
        "value" : "actress",
        "suggested" : true
      } ]
    }
  } ],
  "WARNING" : "DEPRECATED"
}
```

音频样本包含以下录音：*他知道那位年轻女演员的技巧*。根据`wit.ai` API，转录为*他知道了那位年轻女演员*。词错误率为 22%（[`en.wikipedia.org/wiki/Word_error_rate`](https://en.wikipedia.org/wiki/Word_error_rate)）。

# 自动化路由任务

在这一部分，我们将讨论如何在 Python 中自动化路由任务。我们举了两个例子，它们展示了树莓派 Zero 作为个人助手的能力。第一个例子涉及改善通勤，而第二个例子则是帮助提高词汇量。让我们开始吧。

# 改善日常通勤

许多城市和公共交通系统已经开始向公众分享数据，以增加透明度并提高运营效率。交通系统已经开始通过 API 向公众分享公告和交通信息。这使任何人都能开发提供给通勤者信息的移动应用。有时，这有助于缓解公共交通系统内的拥堵。

这个例子是受到一位朋友的启发，他追踪旧金山共享单车站点的自行车可用性。在旧金山湾区，有一个自行车共享计划，让通勤者可以从交通中心租一辆自行车到他们的工作地点。在像旧金山这样拥挤的城市，特定站点的自行车可用性会根据一天的时间而波动。

这位朋友想要根据最近的共享单车站点的自行车可用性来安排他的一天。如果站点上的自行车非常少，这位朋友更喜欢早点出发租一辆自行车。他正在寻找一个简单的技巧，可以在自行车数量低于某个阈值时向他的手机推送通知。旧金山的共享单车计划在[`feeds.bayareabikeshare.com/stations/stations.json`](http://feeds.bayareabikeshare.com/stations/stations.json)上提供了这些数据。

让我们回顾一下构建一个简单的例子，可以使其向移动设备发送推送通知。为了发送移动推送通知，我们将使用**If This Then That**（**IFTTT**）——这是一个使您的项目连接到第三方服务的服务。

在这个例子中，我们将解析以 JSON 格式可用的数据，检查特定站点的可用自行车数量，如果低于指定的阈值，就会触发手机设备上的通知。

让我们开始吧：

1.  第一步是从共享单车服务中检索自行车的可用性。这些数据以 JSON 格式在[`feeds.bayareabikeshare.com/stations/stations.json`](http://feeds.bayareabikeshare.com/stations/stations.json)上提供。数据包括整个网络的自行车可用性。

1.  每个站点的自行车可用性都有一些参数，比如站点 ID、站点名称、地址、可用自行车数量等。

1.  在这个例子中，我们将检索旧金山`Townsend at 7th`站点的自行车可用性。站点 ID 是`65`（在浏览器中打开前面提到的链接以找到`id`）。让我们编写一些 Python 代码来检索自行车可用性数据并解析这些信息：

```py
       import requests 

       BIKE_URL = http://feeds.bayareabikeshare.com/stations 
       /stations.json 

       # fetch the bike share information 
       response = requests.get(BIKE_URL) 
       parsed_data = response.json()
```

第一步是使用`GET`请求（通过`requests`模块）获取数据。`requests`模块提供了内置的 JSON 解码器。可以通过调用`json()`函数来解析 JSON 数据。

1.  现在，我们可以遍历站点的字典，并通过以下步骤找到`Townsend at 7th`站点的自行车可用性：

1.  在检索到的数据中，每个站点的数据都附带一个 ID。问题站点的 ID 是`65`（在浏览器中打开之前提供的数据源 URL 以了解数据格式；数据的片段如下截图所示）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/5dc6a42b-f6ff-49b5-b0e5-01f33cebc4ce.png)使用浏览器获取的自行车共享数据源的片段

1.  我们需要遍历数值并确定站点`id`是否与`Townsend at 7th`的匹配：

```py
              station_list = parsed_data['stationBeanList'] 
              for station in station_list: 
                if station['id'] == 65 and 
                   station['availableBikes'] < 2: 
                  print("The available bikes is %d" % station
                  ['availableBikes'])
```

如果站点上的自行车少于`2`辆，我们会向我们的移动设备推送移动通知。

1.  为了接收移动通知，您需要安装*IF by IFTTT*应用程序（适用于苹果和安卓设备）。

1.  我们还需要在 IFTTT 上设置一个配方来触发移动通知。在[`ifttt.com/`](https://ifttt.com/)注册一个账户。

IFTTT 是一个服务，可以创建连接设备到不同应用程序并自动化任务的配方。例如，可以将树莓派 Zero 跟踪的事件记录到您的 Google Drive 上的电子表格中。

IFTTT 上的所有配方都遵循一个通用模板——*如果这样，那么那样*，也就是说，如果发生了特定事件，那么就会触发特定的动作。例如，我们需要创建一个 applet，以便在收到 web 请求时触发移动通知。

1.  您可以使用您的帐户下拉菜单开始创建一个 applet，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b3366418-76f2-48ad-809c-1b1f1a7430b3.png)开始在 IFTTT 上创建一个配方

1.  它应该带您到一个配方设置页面（如下所示）。点击这个并设置一个传入的 web 请求：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/23037a0e-b3a4-47e9-8049-ddc92161b253.png)点击这个

1.  选择 Maker Webhooks 频道作为传入触发器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/67372bef-0815-42f2-8df2-81aa088e6aab.png)选择 Maker Webhooks 频道

1.  选择接收 web 请求。来自树莓派的 web 请求将作为触发器发送移动通知：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/73429b8a-fcb0-4be5-9e76-bd54cde37d86.png)选择接收 web 请求

1.  创建一个名为`mobile_notify`的触发器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/adc6d023-51ad-4120-8e02-3fcaa1fc4645.png)创建一个名为 mobile_notify 的新触发器

1.  现在是时候为传入触发器创建一个动作了。点击那个。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/07d3564b-95ee-496e-927f-3c66400bc4e5.png)点击这个

1.  选择通知：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/31cf0258-7cb2-4ab3-ab1d-6207f545b4dd.png)选择通知

1.  现在，让我们格式化我们想要在设备上收到的通知：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/624dbdf8-0882-422f-9795-2207e23aa71f.png)为您的设备设置通知

1.  在移动通知中，我们需要接收自行车共享站点上可用自行车的数量。点击+ Ingredient 按钮，选择`Value1`。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/67d4c4f5-3a6b-4c6b-95ea-c1671f8bb5a0.png)

格式化消息以满足您的需求。例如，当树莓派触发通知时，希望以以下格式收到消息：`该回家了！Townsend & 7th 只有 2 辆自行车可用！`

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/21ebe4f5-60ce-42ca-b57a-a7ac6ce9b362.png)

1.  一旦您对消息格式满意，选择创建动作，您的配方就应该准备好了！

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/77fb0b9e-af9f-4ed6-ac95-fd5881e6545e.png)创建一个配方

1.  为了在我们的移动设备上触发通知，我们需要一个 URL 来进行`POST`请求和一个触发键。这在您的 IFTTT 帐户的 Services | Maker Webhooks | Settings 下可用。

触发器可以在这里找到：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b4bd2cc0-41f1-45c2-a1b5-2bccbd8fb0d1.png)

在新的浏览器窗口中打开前面截图中列出的 URL。它提供了`POST`请求的 URL 以及如何进行 web 请求的解释（如下截图所示）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/eb376740-2b7f-4b22-8f8e-76a6d19b7657.png)使用之前提到的 URL 进行 POST 请求（为了隐私而隐藏密钥）

1.  在发出请求时（如 IFTTT 文档中所述），如果我们在请求的 JSON 主体中包括自行车的数量（使用`Value1`），它可以显示在移动通知上。

1.  让我们重新查看 Python 示例，当自行车数量低于一定阈值时进行网络请求。将`IFTTT` URL 和您的 IFTTT 访问密钥（从您的 IFTTT 帐户中检索）保存到您的代码中，如下所示：

```py
       IFTTT_URL = "https://maker.ifttt.com/trigger/mobile_notify/ 
       with/key/$KEY"
```

1.  当自行车数量低于一定阈值时，我们需要使用 JSON 主体中编码的自行车信息进行`POST`请求：

```py
       for station in station_list: 
         if station['id'] == 65 and 
            station['availableBikes'] < 3: 
           print("The available bikes is %d" % 
           station['availableBikes']) 
           payload = {"value1": station['availableBikes']} 
           response = requests.post(IFTTT_URL, json=payload) 
           if response.status_code == 200: 
             print("Notification successfully triggered")
```

1.  在上述代码片段中，如果自行车少于三辆，将使用`requests`模块进行`POST`请求。可用自行车的数量使用键`value1`进行编码：

```py
       payload = {"value1": station['availableBikes']}
```

1.  将所有这些放在一起，我们有这个：

```py
       #!/usr/bin/python3 

       import requests 
       import datetime 

       BIKE_URL = "http://feeds.bayareabikeshare.com/stations/
       stations.json" 
       # find your key from ifttt 
       IFTTT_URL = "https://maker.ifttt.com/trigger/mobile_notify/
       with/key/$KEY" 

       if __name__ == "__main__": 
         # fetch the bike share information 
         response = requests.get(BIKE_URL) 
         parsed_data = response.json() 
         station_list = parsed_data['stationBeanList'] 
         for station in station_list: 
           if station['id'] == 65 and 
              station['availableBikes'] < 10: 
             print("The available bikes is %d" % station
             ['availableBikes']) 
  payload = {"value1": station['availableBikes']} 
             response = requests.post(IFTTT_URL, json=payload) 
             if response.status_code == 200: 
               print("Notification successfully triggered")
```

上述代码示例可与本章一起下载，名称为`bike_share.py`。在设置 IFTTT 上的配方后尝试执行它。如果需要，调整可用自行车数量的阈值。您应该会收到移动设备上的通知：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/0e3e05fa-062c-4929-887e-afabf3fd16d8.png)在您的移动设备上通知

# 读者的挑战

在此示例中，自行车信息被获取和解析，如果必要，将触发通知。您将如何修改此代码示例以确保它在一天中的特定时间执行？（提示：使用`datetime`模块）。

您将如何构建一个作为视觉辅助的桌面显示？

# 项目挑战

尝试找出您所在地区的交通系统是否向其用户提供此类数据。您将如何利用数据帮助通勤者节省时间？例如，您将如何使用此类数据向您的朋友/同事提供交通系统建议？

完成书后，我们将发布一个类似的示例，使用旧金山湾区快速交通（BART）的数据。

# 提高你的词汇量

使用 Python 可以提高您的词汇量！想象一下设置一个大型显示屏，它显眼地安装在某个地方，并且每天更新。我们将使用`wordnik` API（在[`www.wordnik.com/signup`](https://www.wordnik.com/signup)注册 API 密钥）。

1.  第一步是为 python3 安装`wordnik` API 客户端：

```py
       git clone https://github.com/wordnik/wordnik-python3.git
 cd wordnik-python3/
 sudo python3 setup.py install
```

wordnik API 有使用限制。有关更多详细信息，请参阅 API 文档。

1.  让我们回顾一下使用`wordnik` Python 客户端编写我们的第一个示例。为了获取当天的单词，我们需要初始化`WordsApi`类。根据 API 文档，可以这样做：

```py
       # sign up for an API key 
       API_KEY = 'API_KEY' 
       apiUrl = 'http://api.wordnik.com/v4' 
       client = swagger.ApiClient(API_KEY, apiUrl) 
       wordsApi = WordsApi.WordsApi(client)
```

1.  现在`WordsApi`类已初始化，让我们继续获取当天的单词：

```py
       example = wordsApi.getWordOfTheDay()
```

1.  这将返回一个`WordOfTheDay`对象。根据`wordnik` Python 客户端文档，该对象包括不同的参数，包括单词、其同义词、来源、用法等。当天的单词及其同义词可以打印如下：

```py
       print("The word of the day is %s" % example.word) 
       print("The definition is %s" %example.definitions[0].text)
```

1.  将所有这些放在一起，我们有这个：

```py
       #!/usr/bin/python3 

       from wordnik import * 

       # sign up for an API key 
       API_KEY = 'API_KEY' 
       apiUrl = 'http://api.wordnik.com/v4' 

       if __name__ == "__main__": 
         client = swagger.ApiClient(API_KEY, apiUrl) 
         wordsApi = WordsApi.WordsApi(client) 
         example = wordsApi.getWordOfTheDay() 
         print("The word of the day is %s" % example.word) 
         print("The definition is %s" %example.definitions[0].text)
```

上述代码片段可与本章一起下载，名称为`wordOfTheDay.py`。注册 API 密钥，您应该能够检索当天的单词：

```py
       The word of the day is transpare
 The definition is To be, or cause to be, transparent; to appear,
       or cause to appear, or be seen, through something.
```

# 读者的挑战

您将如何将此应用程序守护程序化，以便每天更新当天的单词？（提示：cronjob 或`datetime`）。

# 项目挑战

可以使用`wordnik` API 构建一个单词游戏。想想一个既有趣又有助于提高词汇量的单词游戏。您将如何构建一个提示玩家并接受答案输入的东西？

尝试在显示器上显示当天的单词。您将如何实现这一点？

# 日志记录

日志（[`docs.python.org/3/library/logging.html`](https://docs.python.org/3/library/logging.html)）有助于解决问题。它通过跟踪应用程序记录的事件序列来确定问题的根本原因。让我们通过一个简单的应用程序来回顾日志。为了回顾日志，让我们通过发出一个`POST`请求来回顾它：

1.  日志的第一步是设置日志文件位置和日志级别：

```py
       logging.basicConfig(format='%(asctime)s : %(levelname)s :
       %(message)s', filename='log_file.log', level=logging.INFO)
```

在初始化`logging`类时，我们需要指定日志信息、错误等的格式到文件中。在这种情况下，格式如下：

```py
       format='%(asctime)s : %(levelname)s : %(message)s'
```

日志消息的格式如下：

```py
       2016-10-25 20:28:07,940 : INFO : Starting new HTTPS
       connection (1):
       maker.ifttt.com
```

日志消息保存在名为`log_file.log`的文件中。

日志级别确定我们应用程序所需的日志级别。不同的日志级别包括`DEBUG`、`INFO`、`WARN`和`ERROR`。

在这个例子中，我们将日志级别设置为`INFO`。因此，属于`INFO`、`WARNING`或`ERROR`级别的任何日志消息都将保存到文件中。

如果日志级别设置为`ERROR`，则只有这些日志消息会保存到文件中。

1.  让我们根据`POST`请求的结果记录一条消息：

```py
       response = requests.post(IFTTT_URL, json=payload) 
       if response.status_code == 200: 
         logging.info("Notification successfully triggered") 
       else: 
         logging.error("POST request failed")
```

1.  将所有这些放在一起，我们有：

```py
       #!/usr/bin/python3 

       import requests 
       import logging 

       # find your key from ifttt 
       IFTTT_URL = "https://maker.ifttt.com/trigger/rf_trigger/
       with/key/$key" 

       if __name__ == "__main__": 
         # fetch the bike share information 
         logging.basicConfig(format='%(asctime)s : %(levelname)s
         : %(message)s', filename='log_file.log', level=logging.INFO) 
         payload = {"value1": "Sample_1", "value2": "Sample_2"} 
         response = requests.post(IFTTT_URL, json=payload) 
         if response.status_code == 200: 
           logging.info("Notification successfully triggered") 
         else: 
           logging.error("POST request failed")
```

前面的代码示例（`logging_example.py`）可与本章一起下载。这是 Python 中日志概念的一个非常简单的介绍。

# Python 中的线程

在本节中，我们将讨论 Python 中的线程概念。线程使得能够同时运行多个进程成为可能。例如，我们可以在监听传感器的同时运行电机。让我们通过一个例子来演示这一点。

我们将模拟一个情况，我们希望处理相同类型传感器的事件。在这个例子中，我们只是打印一些内容到屏幕上。我们需要定义一个函数来监听每个传感器的事件：

```py
def sensor_processing(string): 
  for num in range(5): 
    time.sleep(5) 
    print("%s: Iteration: %d" %(string, num))
```

我们可以利用前面的函数同时使用 Python 中的`threading`模块监听三个不同传感器的事件：

```py
thread_1 = threading.Thread(target=sensor_processing, args=("Sensor 1",)) 
thread_1.start() 

thread_2 = threading.Thread(target=sensor_processing, args=("Sensor 2",)) 
thread_2.start() 

thread_3 = threading.Thread(target=sensor_processing, args=("Sensor 3",)) 
thread_3.start()
```

将所有这些放在一起，我们有：

```py
import threading 
import time 

def sensor_processing(string): 
  for num in range(5): 
    time.sleep(5) 
    print("%s: Iteration: %d" %(string, num)) 

if __name__ == '__main__': 
  thread_1 = threading.Thread(target=sensor_processing, args=("Sensor 1",)) 
  thread_1.start() 

  thread_2 = threading.Thread(target=sensor_processing, args=("Sensor 2",)) 
  thread_2.start() 

  thread_3 = threading.Thread(target=sensor_processing, args=("Sensor 3",)) 
  thread_3.start()
```

前面的代码示例（可作为`threading_example.py`下载）启动三个线程，同时监听来自三个传感器的事件。输出看起来像这样：

```py
Thread 1: Iteration: 0 
Thread 2: Iteration: 0 
Thread 3: Iteration: 0 
Thread 2: Iteration: 1 
Thread 1: Iteration: 1 
Thread 3: Iteration: 1 
Thread 2: Iteration: 2 
Thread 1: Iteration: 2 
Thread 3: Iteration: 2 
Thread 1: Iteration: 3 
Thread 2: Iteration: 3 
Thread 3: Iteration: 3 
Thread 1: Iteration: 4 
Thread 2: Iteration: 4 
Thread 3: Iteration: 4
```

# Python 的 PEP8 样式指南

**PEP8**是 Python 的样式指南，它帮助程序员编写可读的代码。遵循某些约定以使我们的代码可读是很重要的。一些编码约定的例子包括以下内容：

+   内联注释应以`# `开头，后面跟着一个空格。

+   变量应该遵循以下约定：`first_var`。

+   避免每行末尾的空格。例如，`if name == "test":`后面不应该有空格。

你可以在[`www.python.org/dev/peps/pep-0008/#block-comments`](https://www.python.org/dev/peps/pep-0008/#block-comments)阅读完整的 PEP8 标准。

# 验证 PEP8 指南

有工具可以验证您的代码是否符合 PEP8 标准。编写代码示例后，请确保您的代码符合 PEP8 标准。可以使用`pep8`包来实现。

```py
    pip3 install pep8
```

让我们检查我们的代码示例是否符合 PEP8 规范。可以按照以下步骤进行：

```py
    pep8 opencv_test.py
```

检查指出了以下错误：

```py
    opencv_test.py:5:50: E231 missing whitespace after ','
 opencv_test.py:6:19: E231 missing whitespace after ','
```

根据输出结果，以下行缺少逗号后的空格，分别是第`5`行和第`6`行：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/1b943d8f-20da-4864-b184-b775bba8fd7b.png)逗号后缺少尾随空格

让我们修复这个问题，并且我们的代码应该遵循 PEP8 规范。重新检查文件，错误将会消失。为了使你的代码可读，总是在将代码提交到公共存储库之前运行 PEP8 检查。

# 总结

在这一章中，我们讨论了 Python 中的高级主题。我们讨论了包括语音识别、构建通勤信息工具以及改善词汇量的 Python 客户端在内的主题。Python 中有许多在数据科学、人工智能等领域广泛使用的高级工具。我们希望本章讨论的主题是学习这些工具的第一步。
