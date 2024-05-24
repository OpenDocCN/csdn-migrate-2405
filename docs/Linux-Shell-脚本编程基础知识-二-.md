# Linux Shell 脚本编程基础知识（二）

> 原文：[`zh.annas-archive.org/md5/0DC4966A30F44E218A64746C6792BE8D`](https://zh.annas-archive.org/md5/0DC4966A30F44E218A64746C6792BE8D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：有效的脚本编写

要在 shell 中编写有效的脚本，非常重要的是要了解 shell 提供的不同实用工具。与其他编程语言类似，shell 编程也需要一种在特定条件下指定跳过或运行某些命令的方法。在 shell 中也需要循环结构来执行元素列表上的某些任务。

在本章中，我们将涵盖诸如`if`、`else`、`case`和`select`之类的主题，这些主题可根据条件运行一定的命令块。我们将看到`for`、`while`和`until`结构，用于在脚本中循环执行一定的命令块。我们将看到在命令或脚本执行后，退出代码如何在了解命令是否成功执行方面发挥重要作用。我们还将看到如何在 shell 中定义函数，从而使我们能够从现在开始编写模块化和可重用的代码。

本章将详细介绍以下主题：

+   退出脚本和退出代码

+   使用测试测试表达式

+   使用`if`和`else`的条件语句

+   索引数组和关联数组

+   使用`for`循环

+   `select`、`while`和`until`循环

+   切换到您的选择

+   使用函数和位置参数

+   使用`xargs`将`stdout`作为参数传递

+   别名

+   `pushd`和`popd`

# 退出脚本和退出代码

我们现在对 shell 脚本文件、命令以及在`bash`中运行它们以获得所需的输出非常熟悉。到目前为止，我们所见过的 shell 脚本示例都是按行运行直到文件末尾。在编写真实世界的 shell 脚本时，情况可能并非总是如此。例如，当发生错误时，不满足某些条件时等等，我们可能需要在脚本中间退出。要退出脚本，使用带有可选返回值的`exit` shell 内置命令。返回值告诉退出代码，也称为返回状态或退出状态。

## 退出代码

每个命令在执行时都会返回一个退出代码。退出代码是了解命令是否成功执行或是否发生了错误的一种方式。根据**POSIX**（**可移植操作系统接口**）标准约定，成功执行的命令或程序返回`0`，而失败执行返回`1`或更高的值。

在 bash 中，要查看上一个命令的退出状态，可以使用“`$?`”。

以下示例显示了成功执行命令的退出代码：

```
$ ls /home  # viewing Content of directory /home
foo

```

现在，要查看上一个执行的命令的退出代码，即`ls /home`，我们将运行以下命令：

```
$ echo $?
0

```

我们看到`ls`命令执行的退出状态为`0`，这意味着它已成功执行。

另一个示例显示了不成功执行命令的退出代码如下：

```
$  ls /root/
ls: cannot open directory /root/: Permission deniedWe see that the ls command execution was unsuccessful with the Permission denied error. To see the exit status, run the following command:

```

```
$ echo $?
2

```

退出状态代码为`2`，高于`0`，表示执行不成功。

## 具有特殊含义的退出代码

在不同的情况下，脚本或命令返回不同的退出代码。在调试脚本或命令时，了解退出代码的含义是有用的。以下表格解释了在命令或脚本执行的不同条件下惯例返回哪个退出代码：

| 退出代码 | 描述 |
| --- | --- |
| 0 | 成功执行 |
| 1 | 一般错误 |
| 2 | 使用 shell 内置命令时出错 |
| 126 | 在执行命令时出现权限问题；我们无法调用请求的命令 |
| 127 | 无法调用请求的命令 |
| 128 | 在脚本中指定无效参数退出。只有 0 到 255 之间的值是有效的退出代码 |
| 128+n | 信号'n'的致命错误 |
| 130 | 使用 Ctl + C 终止脚本 |
| 255* | 超出范围的退出代码 |

保留退出代码 0、1、126-165 和 255，我们在脚本文件中返回退出代码时应使用除这些数字之外的其他数字。

以下示例显示命令返回的不同退出代码：

+   **退出代码 0**：以下是`echo`命令的成功执行：

```
$ echo "Successful Exit code check"
Successful Exit code check
$ echo $?
0

```

+   **退出代码 1**：从`/root`复制文件没有权限，如下所示：

```
$  cp -r /root/ .
cp: cannot access '/root/': Permission denied
$ echo $?
1

```

+   **退出代码 2**：使用无效参数读取 shell 内置如下：

```
$ echo ;;
bash: syntax error near unexpected token ';;'
$ echo $?
2

```

+   **退出代码 126**：将`/usr/bin`目录作为实际上不是命令的命令运行：

```
$ /usr/bin
bash: /usr/bin: Is a directory
$ echo $?
126

```

+   **退出代码 127**：运行一个名为`foo`的命令，实际上并不存在于系统中：

```
$ foo
bash: foo: command not found
$ echo $?
127

```

+   **退出代码 128+n**：通过按*Ctrl* + *C*终止脚本：

```
$ read

^C
$ echo $?
130

```

在这里，*Ctrl* + *C*发送`SIGQUIT`信号，其值为`2`。因此，退出代码为`130`（128 + 2）。

## 具有退出代码的脚本

我们还可以退出 shell 内置命令，并附带退出代码，以了解脚本是否成功运行或遇到任何错误。在调试自己的脚本时，可以使用不同的错误代码来了解错误的实际原因。

当我们在脚本中不提供任何退出代码时，脚本的退出代码由最后执行的命令决定：

```
#!/bin/bash                                                                                                                                                               
# Filename: without_exit_code.sh                                                                                                                                          
# Description: Exit code of script when no exit code is mentioned in script                                                                                                

var="Without exit code in script"
echo $var

cd /root
```

上述脚本没有指定任何退出代码；运行此脚本将得到以下输出：

```
$ sh without_exit_code.sh
Without exit code in script
without_exit_code.sh: line 8: cd: /root: Permission denied
$ echo $?  # checking exit code of script
1

```

此脚本的退出代码为`1`，因为我们没有指定任何退出代码，最后执行的命令是`cd /root`，由于权限问题而失败。

接下来的示例返回退出代码`0`，无论发生任何错误，即脚本成功运行：

```
#!/bin/bash                                                                                                                                                               
# Filename: with_exit_code.sh                                                                                                                                          
# Description: Exit code of script when exit code is mentioned in scr# ipt                                                                                                

var="Without exit code in script"
echo $var

cd /root

exit 0
```

运行此脚本将得到以下结果：

```
$ sh with_exit_code.sh 
Without exit code in script
with_exit_code.sh: line 8: cd: /root: Permission denied
echo $?
0
```

现在，脚本文件返回退出代码为`0`。我们现在知道在脚本中添加退出代码会有什么不同。

另一个具有退出状态代码的示例如下：

```
#!/bin/bash
# Filename: exit_code.sh                                                                                                                                          
# Description: Exit code of script                                                                                            

cmd_foo # running command not installed in system
echo $?

cd /root # Permission problem
echo $?

echo "Hello World!" # Successful echo print
echo $?

exit 200 # Returning script's exit code as 200
```

运行此脚本后的输出如下：

```
$ sh exit_status.sh
exit_code.sh: line 5: cmd_foo: command not found
127
exit_code.sh: line 8: cd: /root: Permission denied
1
Hello World!
0
$ echo $?  # Exit code of script
200

```

如果在脚本中未指定退出代码，则退出代码将是脚本中运行的最后一个命令的退出状态。

# 使用测试检查测试表达式

shell 内置命令`test`可用于检查文件类型和比较表达式的值。语法为`test EXPRESSION`或`test`命令也等同于**[ EXPRESSION ]**。

如果`EXPRESSION`结果为`0`，则返回退出代码`1`（`false`），对于非零的`EXPRESSION`结果，返回`0`（`true`）。

如果未提供`EXPRESSION`，则退出状态设置为`1`（false）。

## 文件检查

可以使用`test`命令对文件进行不同类型的检查；例如，文件存在性检查，目录检查，常规文件检查，符号链接检查等。

可以使用以下表格中的选项对文件进行各种检查：

| 选项 | 描述 |
| --- | --- |
| -e | fileChecks 文件是否存在 |
| -f file | 文件是常规文件 |
| -d file | 文件存在且为目录 |
| -h，-L file | 文件是符号链接 |
| -b file | 文件是块特殊文件 |
| -c file | 文件是字符特殊文件 |
| -S file | 文件是套接字 |
| -p file | 文件是命名管道 |
| -k file | 文件的粘着位已设置 |
| -g file | 文件的设置组 ID（sgid）位已设置 |
| -u file | 文件的设置用户 ID（suid）位已设置 |
| -r file | 文件具有读权限 |
| -w file | 文件具有写权限 |
| -x file | 文件具有执行权限 |
| -t fd | 文件描述符 fd 在终端上打开 |
| file1 -ef file2 | file1 是 file2 的硬链接 |
| file1 -nt file2 | file1 比 file2 更近 |
| file1 -ot file2 | file1 的修改时间早于 file2 |

Shell 脚本对文件执行不同的检查，如下所示：

```
#!/bin/bash
# Filename: file_checks.sh
# Description: Performing different check on and between files

# Checking existence of /tmp/file1
echo -n "Does File /tmp/file1 exist? "
test -e /tmp/file1
echo $?

# Create /tmp/file1
touch /tmp/file1 /tmp/file2
echo -n "Does file /tmp/file1 exist now? "
test -e /tmp/file1
echo $?

# Check whether /tmp is a directory or not
echo -n "Is /tmp a directory? "
test -d /tmp
echo $?

# Checking if sticky bit set on /tmp"
echo -n "Is sticky bit set on /tmp ? "
test -k /tmp
echo $?

# Checking if /tmp has execute permission
echo -n "Does /tmp/ has execute permission ? "
test -x /tmp
echo $?

# Creating another file /tmp/file2
touch /tmp/file2

# Check modification time of /tmp/file1 and /tmp/file2
echo -n "Does /tmp/file1 modified more recently than /tmp/file2 ? "
test /tmp/file1 -nt /tmp/file2
echo $?
```

运行此脚本的输出如下：

```
Does File /tmp/file1 exist? 1
Does file /tmp/file1 exist now? 0
Is /tmp a directory? 0
Is sticky bit set on /tmp ? 0
Does /tmp/ has execute permission? 0
Does /tmp/file1 modified more recently than /tmp/file2 ? 1
```

在我们的输出中，`0`和`1`是在文件上运行测试命令后的`存在`状态。输出`1`表示测试失败，`0`表示测试成功通过。

## 算术检查

我们还可以在整数之间执行算术检查。可以在整数上进行的比较在以下表中解释：

| 比较 | 描述 |
| --- | --- |
| `INTEGER1 -eq INTEGER2` | INTEGER1 等于 INTEGER2 |
| `INTEGER1 -ne INTEGER2` | INTEGER1 不等于 INTEGER2 |
| `INTEGER1 -gt INTEGER2` | INTEGER1 大于 INTEGER2 |
| `INTEGER1 -ge INTEGER2` | INTEGER1 大于或等于 INTEGER2 |
| `INTEGER1 -lt INTEGER2` | INTEGER1 小于 INTEGER2 |
| `INTEGER1 -le INTEGER2` | INTEGER1 小于或等于 INTEGER2 |

Shell 脚本显示了两个整数之间的各种算术检查，如下所示：

```
#!/bin/bash
# Filename: integer_checks.sh
# Description: Performing different arithmetic checks between integers

a=12 b=24 c=78 d=24
echo "a = $a , b = $b , c = $c , d = $d"

echo -n "Is a greater than b ? "
test $a -gt $b
echo $?

echo -n "Is b equal to d ? "
test $b -eq $d
echo $?

echo -n "Is c not equal to d ? "
test $c -ne $d
echo $?
```

运行脚本后的输出如下：

```
a = 12 , b = 24 , c = 78 , d = 24
Is a greater than b ? 1
Is b equal to d ? 0
Is c not equal to d ? 0
```

此外，此处的测试在整数之间运行比较测试后返回退出状态，并在成功时返回`0`（true），在测试失败时返回`1`（false）。

## 字符串检查

命令测试还允许您对字符串进行检查。可能的检查在下表中描述：

| 比较 | 描述 |
| --- | --- |
| `-z STRING` | 字符串的长度为零 |
| `-n STRING` | 字符串的长度不为零 |
| `STRING1 = STRING2` | STRING1 和 STRING2 相等 |
| `SRING1 != STRING2` | STRING1 和 STRING2 不相等 |

Shell 脚本显示了字符串之间的各种字符串检查，如下所示：

```
#!/bin/bash
# Filename: string_checks.sh
# Description: Performing checks on and between strings

str1="Hello" str2="Hell" str3="" str4="Hello"
echo "str1 = $str1 , str2 = $str2 , str3 = $str3 , str4 = $str4"

echo -n "Is str3 empty ? "
test -z $str3
echo $?

echo -n "Is str2 not empty? "
test -n $str2
echo $?

echo -n "Are str1 and str4 equal? "
test $str1 = $str4
echo $?

echo -n "Are str1 and str2 different? "
test $str1 != $str2
echo $?
```

运行脚本后的输出如下：

```
str1 = Hello , str2 = Hell , str3 =  , str4 = Hello
Is str3 empty ? 0
Is str2 not empty? 0
Are str1 and str4 equal? 0
Are str1 and str2 different? 0
```

在这里，如果字符串检查为真，则测试返回`0`退出状态，否则返回`1`。

## 表达式检查

`test`命令还允许您对表达式进行检查。表达式本身也可以包含多个要评估的表达式。可能的检查如下表所示：

| 比较 | 描述 |
| --- | --- |
| `( EXPRESSION )` | 此表达式为真 |
| `! EXPRESSION` | 此表达式为假 |
| `EXPRESSION1 -a EXPRESSION2` | 两个表达式都为真（AND 操作） |
| `EXPRESSION1 -o EXPRESSION2` | 两个表达式中的一个为真（OR 操作） |

Shell 脚本显示了字符串之间的各种字符串检查，如下所示：

```
#!/bin/bash
# Filename: expression_checks.sh
# Description: Performing checks on and between expressions

a=5 b=56
str1="Hello" str2="Hello"

echo "a = $a , b = $b , str1 = $str1 , str2 = $str2"
echo -n "Is a and b are not equal, and str1 and str2 are equal? "
test ! $a -eq $b -a  $str1 = $str2
echo $?

echo -n "Is a and b are equal, and str1 and str2 are equal? "
test $a -eq $b -a  $str1 = $str2
echo $?

echo -n "Does /tmp is a sirectory and execute permission exists? "
test -d /tmp -a  -x /tmp
echo $?

echo -n "Is /tmp file is a block file or write permission exists? "
test -b /tmp -o -w /tmp
echo $?
```

运行此脚本的输出如下：

```
a = 5 , b = 56 , str1 = Hello , str2 = Hello
Is a and b are not equal, and str1 and str2 are equal? 0
Is a and b are equal, and str1 and str2 are equal? 1
Does /tmp is a sirectory and execute permission exists? 0
Is /tmp file is a block file or write permission exists? 0
```

与`test`命令的其他检查类似，`0`退出代码表示表达式评估为真，`1`表示评估为假。

# 使用 if 和 else 的条件语句

Shell 提供了`if`和`else`，根据评估是`true`还是`false`来运行条件语句。如果我们只想在某个条件为`true`时执行某些任务，这将非常有用。

if 的测试条件可以使用测试条件或[条件]给出。我们已经在上一节*使用测试测试表达式*中学习了多个用例和示例。

## 简单的 if 和 else

`if`条件的语法如下：

```
if [ conditional_expression ]
then
  statements
fi
```

如果`conditional_expression`为`true`——也就是说，退出状态为`0`——那么其中的语句将被执行。如果不是，则它将被忽略，`fi`后的下一行将被执行。

`if`和`else`的语法如下：

```
if [ conditional_expression ]
then
  statements
else
  statements
fi
```

有时，当条件不成立时，我们可能希望执行一些语句。在这种情况下，使用`if`和`else`。在这里，如果`conditional_statement`为真，则 if 内的语句将被执行。否则，else 内的语句将被执行。

以下 shell 脚本在文件存在时打印消息：

```
#!/bin/bash
# Filename: file_exist.sh
# Description: Print message if file exists

if [ -e /usr/bin/ls ]
then
        echo "File /usr/bin/ls exists"
fi
```

运行脚本后的输出如下：

```
File /usr/bin/ls exists
```

另一个示例显示了两个整数中的较大者，如下所示：

```
#!/bin/bash
# Filename: greater_integer.sh
# Description: Determining greater among two integers

echo "Enter two integers a and b"
read a b        # Reading input from stdin
echo "a = $a , b = $b"
# Finding greater integer
if test $a -gt $b
then
        echo "a is greater than b"
else
        echo "b is greater than a"
fi
```

运行脚本后的输出如下：

```
$ sh greater_integer.sh
Enter two integers a and b
56 8
a = 56 , b = 8
a is greater than b
```

## if、elif 和 else 语句

在某些情况下，存在超过两个选择，其中只有一个需要执行。`elif`允许您在条件不成立时使用另一个`if`条件，而不是使用`else`。语法如下：

```
if [ conditional_expression1 ]
then
  statements
elif [ conditional_expression2 ]
then
  statements
elif [ conditional_expression3 ]
then
  statements
  # More elif conditions
else
  statements
```

以下 shell 脚本将使`elif`的用法更清晰。此脚本要求用户输入带有绝对路径的有效文件或目录名称。对于有效的常规文件或目录，它显示以下内容：

```
#!/bin/bash
# Filename: elif_usage.sh
# Description: Display content if user input is a regular file or a directoy

echo "Enter a valid file or directory path"
read path
echo "Entered path is $path"

if [ -f $path ]
then
   echo "File is a regular file and its content is:"
   cat $path
elif [ -d $path ]
then
   echo "File is a directory and its content is:"
   ls $path
else
   echo "Not a valid regular file or directory"
fi
```

运行脚本后的输出如下：

```
Enter a valid file or directory path
/home/
Entered path is /home/
File is a directory and its content is:
lost+found  sinny
```

## 嵌套 if

在许多情况下，需要多个`if`条件，因为条件的执行取决于另一个条件的结果。 语法如下：

```
if [ conditional_expression1 ]
then
  if [ conditional_expression2 ]
  then
     statements
     if [conditional_expression3 ]
     then
       statements
     fi
  fi
fi
```

以下脚本示例更详细地解释了嵌套的`if`。 在此脚本中，我们将看到如何找到三个整数值中的最大值：

```
#!/bin/bash
# Filename: nested_if.sh
# Description: Finding greatest integer among 3 by making use of nested if

echo "Enter three integer value"
read a b c
echo "a = $a , b = $b, c = $c"

if [ $a -gt $b ]
then
   if [ $a -gt $c ]
   then
      echo "a is the greatest integer"
   else
     echo "c is the greatest integer"
   fi
else
  if [ $b -gt $c ]
  then
    echo "b is the greatest integer"
  else
    echo "c is the greatest integer"
  fi
fi
```

运行脚本后的输出如下：

```
Enter three integer value
78 110 7
a = 78 , b = 110, c = 7
b is the greatest integer
```

# 索引数组和关联数组

Bash 提供了一个声明变量列表（或数组）的功能，可以是索引数组或关联数组的一维数组。 数组的大小可以是`0`或更多。

## 索引数组

索引数组包含可能已初始化或未初始化的变量。 索引数组的索引从`0`开始。 这意味着数组的第一个元素将从索引`0`开始。

### 数组声明和赋值

可以通过初始化任何索引来声明索引数组，如下所示：

`array_name[index]=value`

在这里，索引可以是任何正整数，或者表达式必须评估为正整数。

另一种声明方式是使用内置的`declare` shell，如下所示：

`declare -a array_name`

我们还可以在声明时使用值初始化数组。 值用括号括起来，每个值用空格分隔，如下所示：

`declare -a array_name=(value1 value2 value3 …)`

### 数组的操作

初始化和声明变量的值是不够的。 当我们对其执行不同的操作以获得所需的结果时，数组的实际用法才体现出来。

可以对索引数组执行以下操作：

+   通过索引访问数组元素：可以通过引用其索引值来访问数组的元素：

```
echo ${array_name[index]}

```

+   打印数组的内容：如果给出数组的索引为`@`或`*`，则可以打印数组的内容：

```
echo ${array_name[*]}
echo ${array_name[@]}

```

+   获取数组的长度：可以使用带有数组变量的`$#`获取数组的长度：

```
echo ${#array_name[@]}
echo ${#array_name[*]}

```

+   获取数组元素的长度：可以使用`$#`获取第 n 个索引的数组元素的长度：

```
echo ${#array_name[n]}

```

+   删除元素或整个数组：可以使用`unset`关键字从数组中删除元素：

```
unset array_name[index]  # Removes value at index
unset array_name  # Deletes entire array

```

以下 shell 脚本演示了对索引数组的不同操作：

```
#!/bin/bash
# Filename: indexed_array.sh
# Description: Demonstrating different operations on indexed array

#Declaring an array conutries and intializing it
declare -a countries=(India Japan Indonesia 'Sri Lanka' USA Canada)

# Printing Length and elements of countries array
echo "Length of array countries = ${#countries[@]}"
echo ${countries[@]}

# Deleting 2nd element of array
unset countries[1]
echo "Updated length and content of countries array"
echo "Length = ${#countries[@]}"
echo ${countries[@]}

# Adding two more countries to array
countries=("${countries[@]}" "Indonesia" "England")
echo "Updated length and content of countries array"
echo "Length = ${#countries[@]}"
echo ${countries[@]}
```

执行此脚本后的输出如下：

```
Length of array countries = 6
India Japan Indonesia Sri Lanka USA Canada
Updated length and content of countries array
Length = 5
India Indonesia Sri Lanka USA Canada
Updated length and content of countries array
Length = 7
India Indonesia Sri Lanka USA Canada Indonesia England
```

## 关联数组

关联数组包含一个元素列表，其中每个元素都有一个键值对。 关联数组的元素不是通过使用整数值`0`到`N`来引用的。 它是通过提供包含相应值的键名来引用的。 每个键名都应该是唯一的。

### 声明和赋值

使用`declare` shell 内置的`-A`选项进行关联数组的声明如下：

```
declare -A array_name

```

关联数组使用键而不是索引在方括号中初始化值，如下所示：

```
array_name[key]=value

```

可以以以下方式初始化多个值：

```
array_name=([key1]=value1 [key2]=value2 ...)

```

### 数组的操作

关联数组的一些操作与索引数组类似，例如打印数组的长度和内容。 操作如下：

+   通过键名访问数组元素；要访问关联数组的元素，请使用唯一键，如下所示：

```
echo ${array_name[key]}
```

+   打印关联数组内容：使用以下语法打印关联数组：

```
echo ${array_name[*]}
echo ${array_name[@]}
Obtaining the length of an array:
echo ${#array_name[@]}
echo ${#array_name[*]}
```

+   获取给定键的值和长度：

```
echo ${array_name[k]}  # Value of key k
echo ${#array_name[k]}  # Length of value of key k
```

+   添加新元素；要在关联数组中添加新元素，请使用`+=`运算符，如下所示：

```
array_name+=([key]=value)
```

+   使用`k`键删除关联数组的元素如下：

```
unset array_name[k]
```

+   删除关联数组`array_name`如下：

```
unset array_name
```

以下 shell 脚本演示了关联数组的不同操作：

```
#!/bin/bash
# Filename: associative_array.sh
# Description: Demonstrating different operations on associative array

# Declaring a new associative array
declare -A student

# Assigning different fields in student array
student=([name]=Foo [usn]=2D [subject]=maths [marks]=67)

# Printing length and content of array student
echo "Length of student array = ${#student[@]}"
echo ${student[@]}

# deleting element with key marks
unset student[marks]
echo "Updated array content:"
echo ${student[@]}

# Adding department in student array
student+=([department]=Electronics)
echo "Updated array content:"
echo ${student[@]}
```

执行此脚本后的输出如下：

```
Length of student array = 4
Foo 67 maths 2D
Updated array content:
Foo maths 2D
Updated array content:
Foo maths Electronics 2D
```

# 使用 for 循环

`for`循环可用于遍历列表中的项目或直到条件为真。

在 bash 中使用`for`循环的语法如下：

```
for item in [list]
do
   #Tasks
done
```

另一种编写`for`循环的方式是 C 的方式，如下所示：

```
for (( expr1; expr2; expr3 ))
  # Tasks
done
```

在这里，`expr1`是初始化，`expr2`是条件，`expr3`是增量。

## 简单迭代

以下 shell 脚本解释了如何使用`for`循环打印列表的值：

```
#!/bin/bash
# Filename: for_loop.sh
# Description: Basic for loop in bash

declare -a names=(Foo Bar Tom Jerry)
echo "Content of names array is:"
for name in ${names[@]}
do
   echo -n "$name "
done
echo
```

脚本的输出如下：

```
Content of names array is:
Foo Bar Tom Jerry
```

## 迭代命令输出

我们知道很多命令会给出多行输出，比如`ls`、`cat`、`grep`等。在许多情况下，循环遍历每行输出并对其进行进一步处理是有意义的。

以下示例循环遍历'`/`'的内容并打印目录：

```
#!/bin/bash
# Filename: finding_directories.sh
# Description: Print which all files in / are directories

echo "Directories in / :"
for file in 'ls /'
do
  if [ -d "/"$file ]
  then
     echo -n  "/$file "
  fi
done
echo
```

运行此脚本后的输出如下：

```
Directories in / :
/bin /boot /dev /etc /home /lib /lib64 /lost+found /media /mnt /opt /proc /root /run /sbin /srv /sys /tmp /usr /var
```

## 为 for 循环指定范围

我们还可以在`for`循环中指定整数范围，并为其指定可选的增量值：

```
#!/bin/bash
# Filename: range_in_for.sh
# Description: Specifying range of numbers to for loop

echo "Numbers between 5 to 10 -"
for num in {5..10}
do
  echo -n "$num "
done

echo
echo "Odd numbers between 1 to 10 -"
for num in {1..10..2}
do
  echo -n "$num "
done
echo
```

运行此脚本后的输出如下：

```
Numbers between 5 to 10 -
5 6 7 8 9 10 
Odd numbers between 1 to 10 -
1 3 5 7 9
```

## 小巧的 for 循环

在某些情况下，我们不想编写脚本然后执行它；相反，我们更喜欢在 shell 中完成工作。在这种情况下，将完整的 for 循环写在一行中非常有用和方便，而不是将其变成多行。

例如，打印 3 到 20 之间 3 的倍数可以使用以下代码完成：

```
$ for num in {3..20..3}; do echo -n "$num " ; done
3 6 9 12 15 18 
```

# 选择、while 和 until 循环

`select`、`while`和`until`循环也用于循环和迭代列表中的每个项目，或者在条件为真时进行轻微变化的语法。

## 使用 select 循环

选择循环有助于以简单格式创建带编号的菜单，用户可以从中选择一个或多个选项。

`select`循环的语法如下：

```
select var in list
do
   # Tasks to perform
done
```

`list`可以在使用`select`循环时预先生成或指定为`[item1 item2 item3 …]`的形式。

例如，考虑一个简单的菜单，列出'`/`'的内容，并要求用户输入一个选项，以便知道它是否是一个目录：

```
#!/bin/bash
# Filename: select.sh
# Description: Giving user choice using select to choose

select file in 'ls /'
do
   if [ -d "/"$file ]
   then
     echo "$file is a directory"
   else
     echo "$file is not a directory"
  fi
done
```

运行脚本后的输出如下：

![使用 select 循环](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_03_01.jpg)

要退出脚本，请按*Ctrl* + *C*。

## while 循环

`while`循环允许您重复任务，直到条件为真。语法与 C 和 C++编程语言中的语法非常相似，如下所示：

```
while [ condition ]
do
   # Task to perform
done
```

例如，读取应用程序的名称并显示该应用程序所有运行实例的 pids，如下所示：

```
#!/bin/bash
# Filename: while_loop.sh
# Description: Using while loop to read user input

echo "Enter application name"
while read line
do
  echo -n "Running PID of application $line :"
  pidof $line
done
```

运行此脚本后的输出如下：

```
Enter application name
firefox
Running PID of application firefox : 1771
bash
Running PID of application bash : 9876 9646 5333 4388 3970 2090 2079 2012 1683 1336
ls
Running PID of application ls: 
systemd
Running PID of application systemd : 1330 1026 1
```

要退出脚本，请按*Ctrl* + *C*。

## 直到循环

`until`循环与`while`循环非常相似，但唯一的区别是它执行代码块，直到条件执行为 false。`until`的语法如下：

```
until condition
do
     # Task to be executed
 done
```

例如，假设我们有兴趣知道应用程序的`pid`，每当它的任何实例正在运行时。为此，我们可以使用`until`并使用`sleep`在一定间隔内检查应用程序的`pidof`。当我们找到`pid`时，我们可以退出`until`循环并打印应用程序运行实例的`pid`。

以下 shell 脚本演示了相同的内容：

```
#!/bin/bash
# Filename: until_loop.sh
# Description: Using until loop to read user input

echo "Enter application name"
read app
until  pidof $app
do
  sleep 5
done
echo "$app is running now with pid 'pidof $app'"
```

执行此脚本后的输出如下：

```
Enter application name
firefox
1867
firefox is running now with pid 1867
```

# 切换到我的选择

Switch 用于根据条件或表达式的结果跳转和运行特定的 case。它作为在 bash 中使用多个**if**的替代方案，并使 bash 脚本更清晰和可读。

`switch`的语法如下：

```
case $variable in
  pattern1)
  # Tasks to be executed
  ;;
  pattern2)
  # Tasks to be executed
  ;;
  …
  pattern n)
  # Tasks to be executed
  ;;
  *)
esac
```

在语法中，`$variable`是需要在提供的选择列表中匹配的表达式或值。

在每个选择中，可以指定一个模式或模式的组合。`;;`告诉 bash 给定选择块的结束。`esac`关键字指定 case 块的结束。

以下是一个示例，用于计算给定路径中文件和目录的数量：

```
#!/bin/bash
# Filename: switch_case.sh
# Description: Using case to find count of directories and files in a # path

echo "Enter target path"
read path
files_count=0
dirs_count=0

for file in 'ls -l $path | cut -d ' ' -f1'
do
  case "$file" in

        d*)
        dirs_count='expr $dirs_count + 1 '
        ;;
        -*)
        files_count='expr $files_count + 1'
        ;;
        *)
  esac
done

echo "Directories count = $dirs_count"
echo "Regular file count = $files_count"
```

运行此脚本后的输出如下：

```
Enter target path
/usr/lib64
Directories count = 134
Regular file count = 1563
```

在这个例子中，我们首先使用`read` shell 内置命令从用户那里读取输入路径。然后，我们将文件和目录计数的计数变量初始化为`0`。此外，我们使用`ls -l $path | cut -d ' ' -f1`来获取路径内容的文件属性的长列表，然后检索其第一列。我们知道`ls -l`的第一列的第一个字符表示文件的类型。如果是`d`，那么它是一个目录，`-`表示一个常规文件。`dirs_count`或`files_count`变量相应地递增。

# 使用 xargs 传递 stdout 作为参数

`xargs`命令用于从标准输入构建和执行命令行。诸如`cp`、`echo`、`rm`、`wc`等命令不从标准输入获取输入，也不从另一个命令的重定向输出获取输入。在这样的命令中，我们可以使用`xargs`将输入作为另一个命令的输出。语法如下：

`xargs [option]`

以下表格解释了一些选项：

| 选项 | 描述 |
| --- | --- |
| -`a` file | 这从文件中读取项目，而不是从 stdin 中读取 |
| `-0`, `--null` | 输入以空字符而不是空格终止 |
| `-t`, `--verbose` | 在执行之前在标准输出上打印命令行 |
| `--show-limits` | 这显示操作系统强加的命令行长度限制 |
| `-P max-procs` | 一次运行最多 max-procs 个进程 |
| `-n max-args` | 最多使用每个命令行的 max-args 参数 |

## 使用 xargs 的基本操作

`xargs`命令可以不带任何选项。它允许您从 stdin 输入，并在调用`ctrl + d`时打印输入的任何内容：

```
$ xargs
Linux shell
scripting 
ctrl + d
Linux shell scripting

```

`--show-limits`选项可用于了解命令行长度的限制：

```
$ xargs --show-limits
Your environment variables take up 4017 bytes
POSIX upper limit on argument length (this system): 2091087
POSIX smallest allowable upper limit on argument length (all systems): 4096
Maximum length of command we could actually use: 2087070
Size of command buffer we are actually using: 131072

```

## 使用 xargs 查找具有最大大小的文件

以下 shell 脚本将解释如何使用`xargs`递归地获取给定目录中具有最大大小的文件：

```
#!/bin/bash
# Filename: max_file_size.sh
# Description: File with maximum size in a directory recursively

echo "Enter path of directory"
read path
echo "File with maximum size:"

find $path -type f | xargs du -h | sort -h | tail -1
```

运行此脚本后的输出如下：

```
Enter path of directory
/usr/bin
File with maximum size:
12M     /usr/bin/doxygen
```

在这个例子中，我们使用`xargs`将从`find`命令获取的每个常规文件传递给大小计算。此外，`du`的输出被重定向到`sort`命令进行人类数字排序，然后我们可以打印最后一行或排序以获得具有最大大小的文件。

## 使用给定模式归档文件

使用`xargs`的另一个有用的例子是归档我们感兴趣的所有文件，并将这些文件作为备份文件保留。

以下 shell 脚本在指定目录中查找所有的 shell 脚本，并为进一步参考创建`tar`文件：

```
#!/bin/bash
# Filename: tar_creation.sh
# Description: Create tar of all shell scripts in a directory

echo "Specify directory path"
read path

find $path -name "*.sh" | xargs tar cvf scripts.tar
```

运行脚本后的输出如下：

```
Specify directory path
/usr/lib64
/usr/lib64/nspluginwrapper/npviewer.sh
/usr/lib64/xml2Conf.sh
/usr/lib64/firefox/run-mozilla.sh
/usr/lib64/libreoffice/ure/bin/startup.sh
```

在这个例子中，搜索所有扩展名为`.sh`的文件，并将其作为参数传递给`tar`命令以创建一个归档。文件`scripts.tar`被创建在调用脚本的目录中。

# 使用函数和位置参数

与其他编程语言类似，函数是一种编写一组操作一次并多次使用的方法。它使代码模块化和可重用。

编写函数的语法如下：

```
function function_name
 {
 # Common set of action to be done
 }

```

这里，`function`是一个关键字，用于指定一个函数，`function_name`是函数的名称；我们也可以以下列方式定义一个函数：

```
function_name()
{
 # Common set of action to be done
}

```

在花括号内编写的操作在调用特定函数时执行。

## 在 bash 中调用函数

考虑以下定义`my_func()`函数的 shell 脚本：

```
#!/bin/bash
# Filename: function_call.sh
# Description: Shows how function is defined and called in bash

# Defining my_func function
my_func()
{
  echo "Function my_func is called"
  return 3
}

my_func # Calling my_func function
return_value=$?
echo "Return value of function = $return_value"
```

要在 shell 脚本中调用`my_func()`，我们只需写出函数的名称：

```
my_func
```

`my_func`函数的返回值为 3。函数的返回值是函数的退出状态。在前面的例子中，`my_func`函数的退出状态被赋给`return_value`变量。

运行上述脚本的结果如下：

```
Function my_func is called
Return value of function = 3
```

函数的返回值是其参数中指定的返回 shell 内置命令。如果没有使用`return`，则函数中执行最后一个命令的退出代码。在这个例子中，退出代码将是`echo`命令的退出代码。

## 向函数传递参数

通过指定函数的第一个名称，后跟以空格分隔的参数，可以为函数提供参数。shell 中的函数不是通过名称而是通过位置来使用参数；我们也可以说 shell 函数使用位置参数。在函数内部，通过变量名`$1`、`$2`、`$3`、`$n`等访问位置参数。

可以使用`$#`获取参数的长度，使用`$@`或`$*`一起获取传递的参数列表。

以下 shell 脚本解释了如何在 bash 中传递参数给函数：

```
#!/bin/bash
# Filename: func_param.sh
# Description: How parameters to function is passed and accessed in bash

upper_case()
{
   if [ $# -eq 1 ]
   then
     echo $1 | tr '[a-z]' '[A-Z]'
   fi
}

upper_case hello
upper_case "Linux shell scripting"
```

上述脚本的输出如下：

```
HELLO
LINUX SHELL SCRIPTING
```

在上面的 shell 脚本示例中，我们两次使用`upper_case()`方法，参数分别为`hello`和`Linux shell scripting`。它们都被转换为大写。类似地，其他函数也可以编写，以避免重复编写工作。

# 别名

shell 中的别名指的是给命令或一组命令取另一个名称。当命令的名称很长时，它非常有用。借助别名，我们可以避免输入更长的名称，并根据自己的方便性来调用命令。

要创建别名，使用别名 shell 内置命令。语法如下：

`alias alias_name="要别名的命令"`

## 创建别名

要以人类可读的格式打印磁盘空间，我们使用带有`-h`选项的`df`命令。通过将`df -h`的别名设置为`df`，我们可以避免反复输入`df -h`。

在将其别名设置为`df -h`之前，`df`命令的输出如下所示：

```
$ df

```

![创建别名](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_03_02.jpg)

现在，要将`df -h`的别名设置为`df`，我们将执行以下命令：

```
$ alias df="df -h"	# Creating alias
$ df

```

获得的输出如下：

![创建别名](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_03_03.jpg)

我们看到，在将`df -h`的别名设置为`df`后，以人类可读的格式打印了默认磁盘空间。

另一个有用的例子是将`rm`命令别名设置为`rm -i`。使用带有`-i`选项的`rm`会在删除文件之前要求用户确认：

```
#!/bin/bash
# Filename: alias.sh
# Description: Creating alias of rm -i

touch /tmp/file.txt
rm /tmp/file.txt        # File gets deleted silently
touch /tmp/file.txt     # Creating again a file
alias rm="rm -i" # Creating alias of rm -i
rm /tmp/file.txt
```

执行上述脚本后的输出如下：

```
rm: remove regular empty file '/tmp/file.txt'? Y
```

我们可以看到，在创建别名后，`rm`在删除`/tmp/file.txt`文件之前要求确认。

## 列出所有别名

要查看当前 shell 已设置的别名，可以使用不带任何参数或带`-p`选项的别名：

```
$ alias
alias df='df -h'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias grep='grep --color=auto'
alias l.='ls -d .* --color=auto'
alias ll='ls -l --color=auto'
alias ls='ls --color=auto'
alias vi='vim'
```

我们可以看到，我们创建的`df`别名仍然存在，并且还有其他已存在的别名。

## 删除别名

要删除已经存在的别名，可以使用`unalias` shell 内置命令：

```
$ unalias df  # Deletes df alias
$ alias -p  # Printing existing aliases
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias grep='grep --color=auto'
alias l.='ls -d .* --color=auto'
alias ll='ls -l --color=auto'
alias ls='ls --color=auto'
alias vi='vim'
```

我们看到`df`别名已被移除。要删除所有别名，请使用`unalias`和`a`选项：

```
$ unalias -a  # Delets all aliases for current shell
$ alias -p

```

我们可以看到所有的别名现在都已经被删除。

# pushd 和 popd

`pushd`和`popd`都是 shell 内置命令。`pushd`命令用于将当前目录保存到堆栈中并移动到新目录。此外，`popd`可用于返回到堆栈顶部的上一个目录。

当我们需要频繁在两个目录之间切换时，它非常有用。

使用`pushd`的语法如下：

`pushd [目录]`

如果未指定目录，`pushd`会将目录更改为堆栈顶部的目录。

使用`popd`的语法如下：

`popd`

使用`popd`开关，我们可以返回到堆栈顶部的上一个目录并弹出该目录。

以下示例计算指定目录中文件或目录的数量，直到一个级别为止：

```
#!/bin/bash
# Filename: pushd_popd.sh
# Description: Count number of files and directories

echo "Enter a directory path"
read path

if [ -d $path ]
then
   pushd $path > /dev/null
   echo "File count in $path directory = 'ls | wc -l'"
   for f in 'ls'
   do
      if [ -d $f ]
      then
         pushd $f > /dev/null
         echo "File count in sub-directory $f = 'ls | wc -l'"
         popd > /dev/null
      fi
   done
   popd > /dev/null
else
  echo "$path is not a directory"
fi
```

运行上述脚本后的输出如下：

```
Enter a directory path
/usr/local   
File count in /usr/local directory = 10
File count in sub-directory bin = 0
File count in sub-directory etc = 0
File count in sub-directory games = 0
File count in sub-directory include = 0
File count in sub-directory lib = 0
File count in sub-directory lib64 = 0
File count in sub-directory libexec = 0
File count in sub-directory sbin = 0
File count in sub-directory share = 3
File count in sub-directory src = 0
```

# 总结

阅读完本章后，你现在应该有足够的信心来使用条件语句、循环等编写有效的 shell 脚本。现在，你也可以使用 shell 中的函数来编写模块化和可重用的代码。了解退出代码的知识将有助于知道命令是否成功执行。你还应该了解一些更有用的 shell 内建命令，比如`alias`、`pushd`和`popd`。

在下一章中，我们将通过了解如何编写可重用的 shell 脚本本身来学习如何模块化我们的脚本，这些脚本可以在 shell 脚本中使用。我们还将看到如何调试我们的 shell 脚本以解决问题。


# 第四章：模块化和调试

在现实世界中，当你编写代码时，你要么永远维护它，要么以后有人接管它并对其进行更改。非常重要的是，您编写一个质量良好的 shell 脚本，以便更容易进一步维护它。同样重要的是，shell 脚本没有错误，以便按预期完成工作。在生产系统上运行的脚本非常关键，因为脚本的任何错误或错误行为可能会造成轻微或重大的损害。为了解决这些关键问题，重要的是尽快解决问题。

在本章中，我们将看到如何编写模块化和可重用的代码，以便快速和无需任何麻烦地维护和更新我们的 shell 脚本应用程序。我们还将看到如何使用不同的调试技术快速轻松地解决 shell 脚本中的错误。我们将看到如何通过在脚本中提供命令行选项的支持为不同的任务提供不同的选择。了解如何在脚本中提供命令行完成甚至会增加使用脚本的便利性。

本章将详细介绍以下主题：

+   将你的脚本模块化

+   将命令行参数传递给脚本

+   调试您的脚本

+   命令完成

# 将你的脚本模块化

在编写 shell 脚本时，有一个阶段我们会觉得一个 shell 脚本文件变得太大，难以阅读和管理。为了避免这种情况发生在我们的 shell 脚本中，保持脚本模块化非常重要。

为了保持脚本的模块化和可维护性，您可以执行以下操作：

+   创建函数而不是一遍又一遍地写相同的代码

+   在一个单独的脚本中编写一组通用的函数和变量，然后源来使用它

我们已经看到如何在第三章 *有效脚本编写*中定义和使用函数。在这里，我们将看到如何将一个更大的脚本分成更小的 shell 脚本模块，然后通过源使用它们。换句话说，我们可以说在`bash`中创建库。

## 源到脚本文件

源是一个 shell 内置命令，它在当前 shell 环境中读取并执行脚本文件。如果一个脚本调用另一个脚本文件的源，那么该文件中可用的所有函数和变量将被加载以供调用脚本使用。

### 语法

使用源的语法如下：

`source <script filename> [arguments]`

或：

`. <script filename> [arguments]`

`脚本文件名`可以带有或不带有路径名。如果提供了绝对或相对路径，它将仅在该路径中查找。否则，将在`PATH`变量中指定的目录中搜索文件名。

`arguments`被视为脚本文件名的位置参数。

`source`命令的退出状态将是在脚本文件中执行的最后一个命令的退出代码。如果脚本文件不存在或没有权限，则退出状态将为`1`。

### 创建一个 shell 脚本库

库提供了一个功能集合，可以被另一个应用程序重用，而无需从头开始重写。我们可以通过将我们的函数和变量放入一个 shell 脚本文件中来创建一个 shell 库，以便重用。

以下的`shell_library.sh`脚本是一个 shell 库的例子：

```
#!/bin/bash
# Filename: shell_library.sh
# Description: Demonstrating creation of library in shell

# Declare global variables
declare is_regular_file
declare is_directory_file

# Function to check file type
function file_type()
{
  is_regular_file=0
  is_directory_file=0
  if [ -f $1 ]
  then
    is_regular_file=1
  elif [ -d $1 ]
  then
    is_directory_file=1
  fi
}

# Printing regular file detail
function print_file_details()
{
   echo "Filename - $1"
   echo "Line count - `cat $1 | wc -l`"
   echo "Size - `du -h $1 | cut -f1`"
   echo "Owner - `ls -l $1 | tr -s ' '|cut -d ' ' -f3`"
   echo "Last modified date - `ls -l $1 | tr -s ' '|cut -d ' ' -f6,7`"
}

# Printing directory details
function print_directory_details()
{
   echo "Directory Name - $1"
   echo "File Count in directory - `ls $1|wc -l`"
   echo "Owner - `ls -ld $1 | tr -s ' '|cut -d ' ' -f3`"
   echo "Last modified date - `ls -ld $1 | tr -s ' '|cut -d ' ' -f6,7`"
}
```

前面的`shell_library.sh` shell 脚本包含了`is_regular_file`和`is_directory_file`全局变量，可以在调用`file_type()`函数后用于知道给定的文件是普通文件还是目录。此外，根据文件的类型，可以打印有用的详细信息。

### 加载一个 shell 脚本库

创建 shell 库是没有用的，除非它在另一个 shell 脚本中使用。我们可以直接在 shell 中使用 shell 脚本库，也可以在另一个脚本文件中使用。要加载 shell 脚本库，我们将使用 source 命令或.（句点字符），然后是 shell 脚本库。

#### 在 bash 中调用 shell 库

要在 shell 中使用`shell_library.sh`脚本文件，我们可以这样做：

```
$ source  shell_library.sh

```

或：

```
$ . shell_library.sh

```

调用它们中的任何一个将使函数和变量可用于当前 shell 中使用：

```
$ file_type /usr/bin
$ echo $is_directory_file
1
$ echo $is_regular_file
0
$ if [ $is_directory_file -eq 1 ]; then print_directory_details /usr/bin; fi
Directory Name - /usr/bin
File Count in directory - 2336
Owner - root
Last modified date - Jul 12
```

当执行`file_type /usr/bin`命令时，将调用带有`/usr/bin`参数的`file_type()`函数。结果是，全局变量`is_directory_file`或`is_regular_file`将设置为`1`（`true`），取决于`/usr/bin`路径的类型。使用 shell 的`if`条件，我们测试`is_directory_file`变量是否设置为`1`。如果设置为`1`，则调用`print_directory_details()`函数，参数为`/usr/bin`，以打印其详细信息。

#### 在另一个 shell 脚本中调用 shell 库

以下示例解释了在 shell 脚本文件中使用 shell 库的用法：

```
#!/bin/bash
# Filename: shell_library_usage.sh
# Description: Demonstrating shell library usage in shell script

# Print details of all files/directories in a directory
echo "Enter path of directory"
read dir

# Loading shell_library.sh module
. $PWD/shell_library.sh

# Check if entered pathname is a directory
# If directory, then print files/directories details inside it
file_type $dir
if [ $is_directory_file -eq 1 ]
then
   pushd $dir > /dev/null       # Save current directory and cd to $dir
   for file in `ls`
   do
     file_type $file
     if [ $is_directory_file -eq 1 ]
     then
       print_directory_details $file
       echo
     elif [ $is_regular_file -eq 1 ]
     then
       print_file_details $file
       echo
     fi
   done
fi
```

在运行`shell_library_usage.sh`脚本后，得到以下输出：

```
$ sh  shell_library_usage.sh	# Few outputs from /usr directory
Enter path of directory
/usr
Directory Name - bin
File Count in directory - 2336
Owner - root
Last modified date - Jul 12

Directory Name - games
File Count in directory - 0
Owner - root
Last modified date - Aug 16

Directory Name - include
File Count in directory - 172
Owner - root
Last modified date - Jul 12

Directory Name - lib
File Count in directory - 603
Owner - root
Last modified date - Jul 12

Directory Name - lib64
File Count in directory - 3380
Owner - root
Last modified date - Jul 12

Directory Name - libexec
File Count in directory - 170
Owner - root
Last modified date - Jul 7
```

### 注意

要加载 shell 脚本库，使用`source`或`.`，然后是`script_filename`。

`source`和`.`（句点字符）都在当前 shell 中执行脚本。`./script`与`. script`不同，因为`./script`在子 shell 中执行脚本，而`. script`在调用它的 shell 中执行。

# 将命令行参数传递给脚本

到目前为止，我们已经看到了诸如`grep`、`head`、`ls`、`cat`等命令的用法。这些命令还支持通过命令行传递参数给命令。一些命令行参数是输入文件、输出文件和选项。根据输出的需要提供参数。例如，执行`ls -l filename`以获得长列表输出，而使用`ls -R filename`用于递归显示目录的内容。

Shell 脚本还支持提供命令行参数，我们可以通过 shell 脚本进一步处理。

命令行参数可以如下给出：

```
<script_file> arg1 arg2 arg3 … argN

```

这里，`script_file`是要执行的 shell 脚本文件，`arg1`、`arg2`、`arg3`、`argN`等是命令行参数。

## 在脚本中读取参数

命令行参数作为位置参数传递给 shell 脚本。因此，`arg1`在脚本中将被访问为`$1`，`arg2`为`$2`，依此类推。

以下 shell 演示了命令行参数的用法：

```
#!/bin/bash
# Filename: command_line_arg.sh
# Description: Accessing command line parameters in shell script

# Printing first, second and third command line parameters"
echo "First command line parameter = $1"
echo "Second command line parameter = $2"
echo "Third command line parameter = $3" 
```

在带有参数运行`command_line_arg.sh`脚本后，得到以下输出：

```
$  sh command_line_arg.sh Linux Shell Scripting
First command line parameter = Linux
Second command line parameter = Shell
Third command line parameter = Scripting
```

以下表格显示了有用的特殊变量，用于获取有关命令行参数的更多信息：

| 特殊变量 | 描述 |
| --- | --- |
| `$#` | 命令行参数的数量 |
| `$*` | 以单个字符串的形式包含所有命令行参数的完整集合，即`'$1 $2 … $n'` |
| `$@` | 完整的命令行参数集合，但每个参数都用单独的引号括起来，即`'$1' '$2' … '$n'` |
| `$0` | shell 脚本本身的名称 |
| `$1, $1, … $N` | 分别指代参数 1、参数 2、…、参数 N |

在脚本中使用`$#`来检查命令行参数的数量将非常有助于进一步处理参数。

以下是另一个接受命令行参数的 shell 脚本示例：

```
#!/bin/bash
# Filename: command_line_arg2.sh
# Description: Creating directories in /tmp

# Check if at least 1 argument is passed in command line
if [ $# -lt 1 ]
then
  echo "Specify minimum one argument to create directory"
  exit 1
else
  pushd /tmp > /dev/null
  echo "Directory to be created are: $@"
  mkdir $@      # Accessing all command line arguments
fi
```

在执行`command_line_arg2.sh`脚本后，得到以下输出：

```
$  sh command_line_arg2.sh a b
Directory to be created are: a b
$  sh command_line_arg2.sh
Specify minimum one argument to create directory

```

## 移动命令行参数

要将命令行参数向左移动，可以使用`shift`内置命令。语法如下：

`shift N`

这里，`N`是它可以向左移动的参数个数。

例如，假设当前的命令行参数是`arg1`，`arg2`，`arg3`，`arg4`和`arg5`。它们可以在 shell 脚本中分别作为`$1`，`$2`，`$3`，`$4`和`$5`访问；`$#`的值为`5`。当我们调用`shift 3`时，参数会被移动`3`个位置。现在，`$1`包含`arg4`，`$2`包含`arg5`。此外，`$#`的值现在是`2`。

以下 shell 脚本演示了`shift`的用法：

```
#!/bin/bash
# Filename: shift_argument.sh
# Description: Usage of shift shell builtin

echo "Length of command line arguments = $#"
echo "Arguments are:"
echo "\$1 = $1, \$2 = $2, \$3 = $3, \$4 = $4, \$5 = $5, \$6 = $6"
echo "Shifting arguments by 3"
shift 3
echo "Length of command line arguments after 3 shift = $#"
echo "Arguments after 3 shifts are"
echo "\$1 = $1, \$2 = $2, \$3 = $3, \$4 = $4, \$5 = $5, \$6 = $6"
```

使用参数`a b c d e f`运行`shift_argument.sh`脚本后获得以下输出：

```
$ sh shift_argument.sh a b c d e f
Length of command line arguments = 6
Arguments are:
$1 = a, $2 = b, $3 = c, $4 = d, $5 = e, $6 = f
Shifting arguments by 3
Length of command line arguments after 3 shift = 3
Arguments after 3 shifts are
$1 = d, $2 = e, $3 = f, $4 = , $5 = , $6 = 

```

## 在脚本中处理命令行选项

提供命令行选项使 shell 脚本更具交互性。从命令行参数中，我们还可以解析选项以供 shell 脚本进一步处理。

以下 shell 脚本显示了带有选项的命令行用法：

```
#!/bin/bash
# Filename: myprint.sh
# Description: Showing how to create command line options in shell script

function display_help()
{
  echo "Usage: myprint [OPTIONS] [arg ...]"
  echo "--help  Display help"
  echo "--version       Display version of script"
  echo  "--print        Print arguments"
}

function display_version()
{
  echo "Version of shell script application is 0.1"
}

function myprint()
{
  echo "Arguments are: $*"
}

# Parsing command line arguments

if [ "$1" != "" ]
then
   case $1 in
        --help ) 
             display_help
             exit 1
            ;;
        --version )
             display_version
             exit 1
             ;;
        --print )
             shift
             myprint $@
             exit 1
            ;;
    *)
    display_help
    exit 1
   esac
fi
```

执行`myprint.sh`脚本后获得以下输出：

```
$ sh myprint.sh --help
Usage: myprint [OPTIONS] [arg ...]
--help      Display help
--version     Display version of script
--print         Print arguments
$ sh myprint.sh --version
Version of shell script application is 0.1
$ sh myprint.sh --print Linux Shell Scripting
Arguments are: Linux Shell Scripting
```

# 调试您的脚本

我们编写不同的 shell 脚本来执行不同的任务。在执行 shell 脚本时，您是否曾遇到过任何错误？答案很可能是肯定的！这是可以预料的，因为几乎不可能总是编写完美的 shell 脚本，没有错误或漏洞。

例如，以下 shell 脚本在执行时是有错误的：

```
#!/bin/bash
# Filename: buggy_script.sh
# Description: Demonstrating a buggy script

a=12 b=8
if [ a -gt $b ]
then
  echo "a is greater than b"
else
  echo "b is greater than a"
fi
```

执行`buggy_script.sh`后获得以下输出：

```
$ sh buggy_script.sh 
buggy_script.sh: line 6: [: a: integer expression expected
b is greater than a

```

从输出中，我们看到错误`[: a: integer expression expected`发生在第 6 行。仅仅通过查看错误消息，通常不可能知道错误的原因，特别是第一次看到错误时。此外，在处理冗长的 shell 脚本时，手动查看代码并纠正错误是困难的。

为了克服在解决 shell 脚本中的错误或漏洞时遇到的各种麻烦，最好调试代码。调试 shell 脚本的方法如下：

+   在脚本的预期错误区域使用`echo`打印变量或要执行的命令的内容。

+   在运行脚本时使用`-x`调试整个脚本

+   使用 set 内置命令在脚本内部使用`-x`和`+x`选项调试脚本的一部分

## 使用 echo 进行调试

`echo`命令非常有用，因为它打印提供给它的任何参数。当我们在执行脚本时遇到错误时，我们知道带有错误消息的行号。在这种情况下，我们可以使用`echo`在实际执行之前打印将要执行的内容。

在我们之前的例子`buggy_script.sh`中，我们在第 6 行得到了一个错误——即`if [ a -gt $b ]`——在执行时。我们可以使用`echo`语句打印实际将在第 6 行执行的内容。以下 shell 脚本在第 6 行添加了`echo`，以查看最终将在第 6 行执行的内容：

```
#!/bin/bash
# Filename: debugging_using_echo.sh
# Description: Debugging using echo

a=12 b=8
echo "if [ a -gt $b ]"
exit
if [ a -gt $b ]
then
  echo "a is greater than b"
else
  echo "b is greater than a"
fi
```

我们现在将按以下方式执行`debugging_using_echo.sh`脚本：

```
$ sh debugging_using_echo.sh
if [ a -gt 8 ]

```

我们可以看到字符`a`正在与`8`进行比较，而我们期望的是变量`a`的值。这意味着我们错误地忘记了在`a`中使用`$`来提取变量`a`的值。

## 使用-x 调试整个脚本

使用`echo`进行调试很容易，如果脚本很小，或者我们知道问题出在哪里。使用`echo`的另一个缺点是，每次我们进行更改，都必须打开一个 shell 脚本，并相应地修改`echo`命令。调试后，我们必须记住删除为调试目的添加的额外`echo`行。

为了克服这些问题，bash 提供了`-x`选项，可以在执行 shell 脚本时使用。使用`-x`选项运行脚本会以调试模式运行脚本。这会打印所有要执行的命令以及脚本的输出。

以以下 shell 脚本为例：

```
#!/bin/bash
# Filename : debug_entire_script.sh
# Description: Debugging entire shell script using -x

# Creating diretcories in /tmp
dir1=/tmp/$1
dir2=/tmp/$2
mkdir $dir1 $dir2
ls -ld $dir1
ls -ld $dir2
rmdir $dir1
rmdir $dir2
```

现在，我们将按以下方式运行前述脚本：

```
$ sh debug_entire_script.sh pkg1
mkdir: cannot create directory '/tmp/': File exists
drwxrwxr-x. 2 skumari skumari 40 Jul 14 01:47 /tmp/pkg1
drwxrwxrwt. 23 root root 640 Jul 14 01:47 /tmp/
rmdir: failed to remove '/tmp/': Permission denied

```

它会给出`/tmp/`目录已经存在的错误。通过查看错误，我们无法知道为什么它要创建`/tmp`目录。为了跟踪整个代码，我们可以使用带有`-x`选项运行`debug_entire_script.sh`脚本：

```
$ sh -x debug_entire_script.sh pkg1
+ dir1=/tmp/pkg1
+ dir2=/tmp/
+ mkdir /tmp/pkg1 /tmp/
mkdir: cannot create directory '/tmp/': File exists
+ ls -ld /tmp/pkg1
drwxrwxr-x. 2 skumari skumari 40 Jul 14 01:47 /tmp/pkg1
+ ls -ld /tmp/
drwxrwxrwt. 23 root root 640 Jul 14 01:47 /tmp/
+ rmdir /tmp/pkg1
+ rmdir /tmp/
rmdir: failed to remove '/tmp/': Permission denied

```

我们可以看到`dir2`是`/tmp/`。这意味着没有输入来创建第二个目录。

使用`-v`选项以及`-x`使得调试更加详细，因为`-v`会显示输入行：

```
$ sh -xv debug_entire_script.sh pkg1
#!/bin/bash
# Filename : debug_entire_script.sh
# Description: Debugging entire shell script using -x

# Creating diretcories in /tmp
dir1=/tmp/$1
+ dir1=/tmp/pkg1
dir2=/tmp/$2
+ dir2=/tmp/
mkdir $dir1 $dir2
+ mkdir /tmp/pkg1 /tmp/
mkdir: cannot create directory '/tmp/': File exists
ls -ld $dir1
+ ls -ld /tmp/pkg1
drwxrwxr-x. 2 skumari skumari 40 Jul 14 01:47 /tmp/pkg1
ls -ld $dir2
+ ls -ld /tmp/
drwxrwxrwt. 23 root root 640 Jul 14 01:47 /tmp/
rmdir $dir1
+ rmdir /tmp/pkg1
rmdir $dir2
+ rmdir /tmp/
rmdir: failed to remove '/tmp/': Permission denied
```

通过详细输出，很明显`dir1`和`dir2`变量期望从命令行参数中提供两个参数。因此，必须从命令行提供两个参数：

```
$  sh  debug_entire_script.sh pkg1 pkg2
drwxrwxr-x. 2 skumari skumari 40 Jul 14 01:50 /tmp/pkg1
drwxrwxr-x. 2 skumari skumari 40 Jul 14 01:50 /tmp/pkg2

```

现在，脚本可以正常运行而不会出现任何错误。

### 注意

不再需要从命令行传递`-xv`选项给 bash，我们可以在脚本文件的`shebang`行中添加它，即`#!/bin/bash -xv`。

## 使用设置选项调试脚本的部分

调试 shell 脚本时，并不总是需要一直调试整个脚本。有时，调试部分脚本更有用且节省时间。我们可以使用`set`内置命令在 shell 脚本中实现部分调试：

```
set -x  (Start debugging from here)
set +x  (End debugging here)
```

我们可以在 shell 脚本的多个位置使用`set +x`和`set -x`，具体取决于需要。当执行脚本时，它们之间的命令将与输出一起打印出来。

考虑以下 shell 脚本作为示例：

```
#!/bin/bash
# Filename: eval.sh
# Description: Evaluating arithmetic expression

a=23
b=6
expr $a + $b
expr $a - $b
expr $a * $b
```

执行此脚本会得到以下输出：

```
$ sh eval.sh
29
17
expr: syntax error
```

我们得到了一个语法错误，最有可能是第三个表达式，即`expr $a * $b`。

为了调试，在`expr $a * $b`之前使用`set -x`，之后使用`set +x`。

另一个带有部分调试的脚本`partial_debugging.sh`如下：

```
#!/bin/bash
# Filename: partial_debugging.sh
# Description: Debugging part of script of eval.sh

a=23
b=6
expr $a + $b

expr $a - $b

set -x
expr $a * $b
set +x
```

执行`partial_debugging.sh`脚本后得到以下输出：

```
$  sh partial_debugging.sh
29
17
+ expr 23 eval.sh partial_debugging.sh 6
expr: syntax error
+ set +x
```

从前面的输出中，我们可以看到`expr $a * $b`被执行为`expr 23 eval.sh partial_debugging.sh 6`。这意味着，bash 在执行乘法时，扩展了`*`作为当前目录中的任何内容的行为。因此，我们需要转义字符`*`的行为，以防止其被扩展，即`expr $a \* $b`。

脚本`eval_modified.sh`是`eval.sh`脚本的修改版本：

```
#!/bin/bash
# Filename: eval_modified.sh
# Description: Evaluating arithmetic expression

a=23
b=6
expr $a + $b
expr $a - $b
expr $a \* $b
```

现在，运行`eval_modified.sh`的输出将如下所示：

```
$  sh eval_modified.sh 
29
17
138
```

脚本现在可以完美运行而不会出现任何错误。

除了我们在调试中学到的内容，您还可以使用`bashdb`调试器来更好地调试 shell 脚本。`bashdb`的源代码和文档可以在[`bashdb.sourceforge.net/`](http://bashdb.sourceforge.net/)找到。

# 命令完成

在命令行上工作时，每个人都必须执行一些常见任务，比如输入命令、选项、输入/输出文件路径和其他参数。有时，由于命令名称中的拼写错误，我们会写错命令名称。此外，输入一个很长的文件路径将很难记住。例如，如果我们想要递归查看路径为`/dir1/dir2/dir3/dir4/dir5/dir6`的目录的内容，我们将不得不运行以下命令：

```
$ ls -R /dir1/dir2/dir3/dir4/dir5/dir6

```

我们可以看到这个目录的路径非常长，很容易在输入完整路径时出错。由于这些问题，使用命令行将花费比预期更长的时间。

为了解决所有这些问题，shell 支持一个非常好的功能，称为命令完成。除了其他 shell 外，bash 也非常好地支持命令完成。

大多数 Linux 发行版，例如 Fedora、Ubuntu、Debian 和 CentOS，都预先安装了核心命令的 bash 完成。如果没有可用，可以使用相应的发行版软件包管理器下载，软件包名称为`bash-completion`。

shell 中的命令完成允许您自动完成部分输入的命令的其余字符，提供与给定命令相关的可能选项。它还建议并自动完成部分输入的文件路径。

要在 bash 中启用自动完成功能，使用*Tab*键。在输入命令时，如果单个命令匹配，单个`TAB`将自动完成命令，双[TAB]将列出所有以部分输入的命令开头的可能命令。

例如：

```
$ gr[TAB]      # Nothing happens
$ gre[TAB]      # Autocompletes to grep
$ grep[TAB][TAB]  # Lists commands installed in system and starts with grep
grep            grep-changelog  grepdiff 

```

现在，假设我们想要查看`/usr/share/man/`目录的内容，我们将不得不输入`ls /usr/share/man/`。使用 bash 完成，输入以下命令：

```
$ ls /u[TAB]/sh[TAB]/man

```

Bash 完成将自动完成缺少的部分路径，命令将变为：

```
$ ls /usr/share/man

```

## 使用 complete 管理 bash 完成

`complete`是一个内置的 shell，可用于查看系统中可用命令的 bash 完成规范。它还用于修改、删除和创建 bash 完成。

### 查看现有的 bash 完成

要了解现有的 bash 完成，请使用`complete`命令，带有或不带`-p`选项：

```
$ complete -p

```

以下是前述命令的一些输出：

```
complete cat  # No completion output
complete -F _longopt grep  # Completion as files from current directory
complete -d pushd  # Completion as directories from current directory
complete -c which  # Completion as list of all available commands

```

要在这些命令上看到 bash 完成，输入以下命令：

这将列出所有文件/目录，包括隐藏的文件/目录：

```
$ grep [TAB][TAB]

```

这将列出所有文件/目录，包括隐藏的文件/目录：

$ 猫[TAB][TAB]

这尝试列出系统中所有可用的命令。按下*y*将显示命令，按下*n*将不显示任何内容。

```
$ complete -c which [TAB][TAB]
 Display all 3205 possibilities? (y or n)

```

### 修改默认的 bash 完成行为

我们还可以使用 complete shell 内置命令修改给定命令的现有 bash 完成行为。

以下命令用于更改`which`命令的行为，不显示任何选项：

```
$ complete which
$ which [TAB][TAB]  # No auto completion option will be shown

```

以下命令用于更改`ls`命令的标签行为，仅显示目录列表作为 bash 完成：

```
$ ls ~/[TAB][TAB]    # Displays directories and file as  auto-completion
file1.sh file2.txt dir1/ dir2/ dir3/
$ complete -d ls
$ ls ~/[TAB][TAB]    # Displays only directory name as  auto-completion
dir1/ dir2/ dir3/

```

### 删除 bash 完成规范

我们可以使用 shell 内置的`complete`命令和`-r`选项删除命令的 bash 完成规范。

语法如下：

```
complete -r command_name

```

将以下内容视为示例：

```
$ complete | grep which  # Viewing bash completion specification for which
complete -c which
$ complete -r which     # Removed bash completion specification for which
$ complete | grep which  # No output

```

如果没有给出`command_name`作为`complete -r`的参数，所有完成规范都将被删除：

```
$ complete -r
$ complete

```

## 为自己的应用程序编写 bash 完成

bash-completion 包不为任何外部工具提供自动完成功能。假设我们想创建一个具有多个选项和参数的工具。要为其选项添加 bash 完成功能，我们必须创建自己的 bash 完成文件并将其源化。

例如，软件包管理器如`dnf`和`apt-get`都有自己的 bash 完成文件，以支持其选项的自动完成：

```
$ dnf up[TAB][TAB]
update      updateinfo  update-to   upgrade     upgrade-to 
$ apt-get up[TAB][TAB]
update upgrade

```

将以下 shell 脚本视为示例：

```
#!/bin/bash
# Filename: bash_completion_example.sh
# Description: Example demonstrating bash completion feature for command options

function help()
{
  echo "Usage: print [OPTIONS] [arg ...]"
  echo "-h|--help    Display help"
  echo "-v|--version Display version of script"
  echo "-p|--print     Print arguments"
}

function version()
{
  echo "Version of shell script application is 0.1"
}

function print()
{
  echo "Arguments are: $*"
}

# Parsing command line arguments

while [ "$1" != "" ]
do
   case $1 in
        -h | --help ) 
             help
             exit 1
            ;;
        -v | --version )
             version
             exit 1
             ;;
        -p | --print )
             shift
             print $@
             exit 1
            ;;
    *)
    help
    exit 1
   esac
done
```

要了解`bash_completion_example.sh`中支持的选项，我们将运行`--help`选项：

```
$ chmod +x bash_completion_example.sh	# Adding execute permission to script
$ ./bash_completion_example.sh --help
Usage: print [OPTIONS] [arg ...]
-h|--help    Display help
-v|--version Display version of script
-p|--print     Print arguments

```

所以，支持的选项是`-h`，`--help`，`-v`，`--version`，`-p`和`--print`。

要编写 bash 完成，需要以下 bash 内部变量的信息：

| Bash 变量 | 描述 |
| --- | --- |
| `COMP_WORDS` | 在命令行上键入的单词数组 |
| `COMP_CWORD` | 包含当前光标位置的单词的索引。 |
| `COMPREPLY` | 一个数组，它保存在按下[TAB][TAB]后显示的完成结果 |

`compgen`是一个内置的 shell 命令，根据选项显示可能的完成。它用于在 shell 函数中生成可能的完成。

### bash 完成的示例

我们的 shell 脚本`bash_completion_example`的 bash 完成文件将如下所示：

```
# Filename: bash_completion_example
# Description: Bash completion for bash_completion_example.sh

_bash_completion_example()
{
    # Declaring local variables
    local cur prev opts
    # An array variable storing the possible completions
    COMPREPLY=()
    # Save current word typed on command line in  cur variable
    cur="${COMP_WORDS[COMP_CWORD]}"
    # Saving previous word typed on command line in prev variable
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    # Save all options provided by application in variable opts
    opts="-h -v -p --help --verbose --print"

    # Checking "${cur} == -*" means that perform completion only if current
    # word starts with a dash (-), which suggest that user is trying to complete an option.
    # Variable COMPREPLY contains the match of the current word "${cur}" against the list
    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}

# Register _bash_completion_example to provide completion
# on running script bash_completion_example.sh
complete -F _bash_completion_example ./bash_completion_example.sh
```

根据惯例，bash 完成函数名称应以下划线(_)开头，后跟应用程序的名称，即`_bash_completion_example`。此外，我们将 bash 变量`COMPREPLY`重置为清除任何先前遗留的数据。然后，我们声明并设置`cur`变量为命令行的当前单词，`prev`变量为命令行中的前一个单词。另一个变量`opts`被声明并初始化为应用程序识别的所有选项；在我们的情况下，它们是`-h -v -p --help --verbose –print`。条件`if [[ ${cur} == -* ]]`检查当前单词是否等于`-*`，因为我们的选项以`-`开头，后跟任何其他字符。如果为`true`，则使用`compgen` shell 内置和`-W`选项显示所有匹配的选项。

### 运行创建的 bash 完成。

为了运行创建的 bash 完成，最简单的方法是将其源到`source bash_completion_example shell script`，然后运行脚本或命令：

```
$ source ./bash_completion_example
Now,  execute shell script:
$ ./bash_completion_example.sh -[TAB][TAB]
-h         --help     -p         --print    -v         --verbose
$ ./bash_completion_example.sh --[TAB][TAB]
--help     --print    --verbose
$  ./bash_completion_example.sh –-p[TAB]

```

在这里，`--p[TAB]`会自动完成为`-–print`。

# 总结

阅读完本章后，你现在应该能够编写一个易于维护和修改的 shell 脚本。现在，你知道如何在自己的脚本中使用现有的 shell 脚本库，使用`source`命令。你还熟悉了使用不同的调试技术来修复 shell 脚本中的错误和 bug。你还应该知道如何通过接受命令行参数并为其提供 bash 完成功能来编写脚本。

在下一章中，我们将看到如何查看、更改、创建和删除环境变量，以满足运行我们的应用程序的要求。
