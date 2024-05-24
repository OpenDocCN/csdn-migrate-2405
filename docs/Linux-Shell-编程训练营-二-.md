# Linux Shell 编程训练营（二）

> 原文：[`zh.annas-archive.org/md5/65C572CE82539328A9B0D1458096FD51`](https://zh.annas-archive.org/md5/65C572CE82539328A9B0D1458096FD51)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：创建交互式脚本

本章展示了如何读取键盘以创建交互式脚本。

本章涵盖的主题有：

+   如何使用`read`内置命令查询键盘。

+   使用`read`的不同方式。

+   使用陷阱（中断）。

读者将学习如何创建交互式脚本。

到目前为止我们看过的脚本都没有太多用户交互。`read`命令用于创建可以查询键盘的脚本。然后根据输入采取行动。

这是一个简单的例子：

# 第五章 - 脚本 1

```
#!/bin/sh
#
# 5/16/2017
#
echo "script1 - Linux Scripting Book"

echo "Enter 'q' to quit."
rc=0
while [ $rc -eq 0 ]
do
 echo -n "Enter a string: "
 read str
 echo "str: $str"
 if [ "$str" = "q" ] ; then
  rc=1
 fi
done

echo "End of script1"
exit 0
```

在我的系统上运行时的输出如下：

![第五章 - 脚本 1](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_01.jpg)

这是一个在您的系统上运行的好例子。尝试几种不同的字符串、数字等。注意返回的字符串包含空格、特殊字符等。你不必引用任何东西，如果你这样做了，那些也会被返回。

您还可以使用`read`命令在脚本中加入简单的暂停。这将允许您在屏幕上滚动之前看到输出。它也可以在调试时使用，将在第九章 *调试脚本*中显示。

以下脚本显示了如何在输出到屏幕的最后一行时创建暂停：

## 第五章 - 脚本 2

```
#!/bin/sh
#
# 5/16/2017
# Chapter 5 - Script 2
#
linecnt=1                    # line counter
loop=0                       # loop control var
while [ $loop -eq 0 ]
do
 echo "$linecnt  $RANDOM"    # display next random number
 let linecnt++
 if [ $linecnt -eq $LINES ] ; then
  linecnt=1
  echo -n "Press Enter to continue or q to quit: "
  read str                   # pause
  if [ "$str" = "q" ] ; then
   loop=1                    # end the loop
  fi
 fi
done

echo "End of script2"
exit 0
```

在我的系统上运行时的输出如下：

![第五章 - 脚本 2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_02.jpg)

我按了两次*Enter*，然后在最后一个上按了*Q*和*Enter*。

让我们尝试一些更有趣的东西。下一个脚本显示了如何用从键盘获取的值填充数组：

## 第五章 - 脚本 3

```
#!/bin/sh
#
# 5/16/2017
#
echo "script3 - Linux Scripting Book"

if [ "$1" = "--help" ] ; then
 echo "Usage: script3"
 echo " Queries the user for values and puts them into an array."
 echo " Entering 'q' will halt the script."
 echo " Running 'script3 --help' shows this Usage message."
 exit 255
fi

x=0                          # subscript into array
loop=0                       # loop control variable
while [ $loop -eq 0 ]
do
 echo -n "Enter a value or q to quit: "
 read value
 if [ "$value" = "q" ] ; then
  loop=1
 else
  array[$x]="$value"
  let x++
 fi
done

let size=x
x=0
while [ $x -lt $size ]
do
 echo "array $x: ${array[x]}"
 let x++
done

echo "End of script3"
exit 0
```

和输出：

![第五章 - 脚本 3](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_03.jpg)

由于这个脚本不需要任何参数，我决定添加一个`Usage`语句。如果用户使用`--help`运行它，这将显示，并且在许多系统脚本和程序中是一个常见的特性。

这个脚本中唯一新的东西是`read`命令。`loop`和`array`变量在之前的章节中已经讨论过。再次注意，使用`read`命令，你输入的就是你得到的。

现在让我们创建一个完整的交互式脚本。但首先我们需要检查当前终端的大小。如果太小，你的脚本输出可能会变得混乱，用户可能不知道原因或如何修复。

以下脚本包含一个检查终端大小的子例程：

## 第五章 - 脚本 4

```
#!/bin/sh
#
# 5/16/2017
#
echo "script4 - Linux Scripting Book"

checktermsize()
{
 rc1=0                       # default is no error
 if [[ $LINES -lt $1 || $COLUMNS -lt $2 ]] ; then
  rc1=1                      # set return code
 fi
 return $rc1
}

rc=0                         # default is no error
checktermsize 40 90          # check terminal size
rc=$?
if [ $rc -ne 0 ] ; then
 echo "Return code: $rc from checktermsize"
fi

exit $rc
```

在您的系统上以不同大小的终端运行此脚本以检查结果。从代码中可以看出，如果终端比所需的大，那没问题；只是不能太小。

### 注意

关于终端大小的一点说明：当使用`tput`光标移动命令时，请记住是先行后列。然而，大多数现代 GUI 是按列然后行。这是不幸的，因为很容易把它们弄混。

现在让我们看一个完整的交互式脚本：

## 第五章 - 脚本 5

```
#!/bin/sh
#
# 5/27/2017
#
echo "script5 - Linux Scripting Book"

# Subroutines
cls()
{
 tput clear
}

move()                       # move cursor to row, col
{
 tput cup $1 $2
}

movestr()                    # move cursor to row, col
{
 tput cup $1 $2
 echo -n "$3"                # display string
}

checktermsize()
{
 rc1=0                       # default is no error
 if [[ $LINES -lt $1 || $COLUMNS -lt $2 ]] ; then
  rc1=1                      # set return code
 fi
 return $rc1
}

init()                       # set up the cursor position array
{
 srow[0]=2;  scol[0]=7       # name
 srow[1]=4;  scol[1]=12      # address 1
 srow[2]=6;  scol[2]=12      # address 2
 srow[3]=8;  scol[3]=7       # city
 srow[4]=8;  scol[4]=37      # state
 srow[5]=8;  scol[5]=52      # zip code
 srow[6]=10; scol[6]=8       # email
}

drawscreen()                 # main screen draw routine
{
 cls                         # clear the screen
 movestr 0 25 "Chapter 5 - Script 5"
 movestr 2 1 "Name:"
 movestr 4 1 "Address 1:"
 movestr 6 1 "Address 2:"
 movestr 8 1 "City:"
 movestr 8 30 "State:"
 movestr 8 42 "Zip code:"
 movestr 10 1 "Email:"
}

getdata()
{
 x=0                         # array subscript
 rc1=0                       # loop control variable
 while [ $rc1 -eq 0 ]
 do
  row=${srow[x]}; col=${scol[x]}
  move $row $col
  read array[x]
  let x++
  if [ $x -eq $sizeofarray ] ; then
   rc1=1
  fi
 done
 return 0
}

showdata()
{
 fn=0
 echo ""
 read -p "Enter filename, or just Enter to skip: " filename
 if [ -n "$filename" ] ; then       # if not blank
  echo "Writing to '$filename'"
 fn=1                       # a filename was given
 fi
 echo ""                     # skip 1 line
 echo "Data array contents: "
 y=0
 while [ $y -lt $sizeofarray ]
 do
  echo "$y - ${array[$y]}"
  if [ $fn -eq 1 ] ; then
   echo "$y - ${array[$y]}">>"$filename"
  fi
  let y++
 done
 return 0
}

# Code starts here
sizeofarray=7                # number of array elements

if [ "$1" = "--help" ] ; then
 echo "Usage: script5 --help"
 echo " This script shows how to create an interactive screen program."
 exit 255
fi

checktermsize 25 80
rc=$?
if [ $rc -ne 0 ] ; then
 echo "Please size the terminal to 25x80 and try again."
 exit 1
fi

init                         # initialize the screen array
drawscreen                   # draw the screen
getdata                      # cursor movement and data input routine
showdata                     # display the data

exit 0
```

这是一些示例输出：

![第五章 - 脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_04.jpg)

这里有很多新信息，让我们来看看。首先定义了子例程，你可以看到我们从前面的*脚本 4*中包含了`checktermsize`子例程。

`init`例程设置了光标放置数组。将初始值放入子例程是良好的编程实践，特别是如果它将被再次调用。

`drawscreen`例程显示初始表单。请注意，我可以在这里使用`srow`和`scol`数组中的值，但我不想让脚本看起来太乱。

非常仔细地看`getdata`例程，因为这是乐趣开始的地方：

+   首先，数组下标`x`和控制变量`rc1`被设置为`0`。

+   在循环中，光标放置在第一个位置（`Name:`）。

+   查询键盘，用户的输入进入子`x`的数组。

+   `x`增加，我们进入下一个字段。

+   如果`x`等于数组的大小，我们离开循环。请记住我们从`0`开始计数。

`showdata`例程显示数组数据，然后我们就完成了。

### 提示

请注意，如果使用`--help`选项运行脚本，则会显示`Usage`消息。

这只是一个交互式脚本的小例子，展示了基本概念。在后面的章节中，我们将更详细地讨论这个问题。

`read`命令可以以多种不同的方式使用。以下是一些示例：

```
read var
Wait for input of characters into the variable var.
read -p "string" var
Display contents of string, stay on the line, and wait for input.

read -p "Enter password:" -s var
Display "Enter password:", but do not echo the typing of the input. Note that a carriage return is not output after Enter is pressed.

read -n 1 var
```

`-n`选项意味着等待那么多个字符，然后继续，它不会等待*Enter*按键。

在这个例子中，它将等待 1 个字符，然后继续。这在实用脚本和游戏中很有用：

## 第五章-脚本 6

```
#!/bin/sh
#
# 5/27/2017
#
echo "Chapter 5 - Script 6"

rc=0                         # return code
while [ $rc -eq 0 ]
do
 read -p "Enter value or q to quit: " var
 echo "var: $var"
 if [ "$var" = "q" ] ; then
  rc=1
 fi
done

rc=0                         # return code
while [ $rc -eq 0 ]
do
 read -p "Password: " -s var
 echo ""                     # carriage return
 echo "var: $var"
if [ "$var" = "q" ] ; then
  rc=1
 fi
done

echo "Press some keys and q to quit."
rc=0                         # return code
while [ $rc -eq 0 ]
do
 read -n 1 -s var            # wait for 1 char, does not output it
 echo $var                   # output it here
 if [ "$var" = "q" ] ; then
  rc=1
 fi
done

exit $rc
```

输出：

![第五章-脚本 6](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_05.jpg)

脚本中的注释应该使这个脚本相当容易理解。`read`命令还有一些其他选项，其中一个将在下一个脚本中显示。

通过使用所谓的陷阱，还有另一种查询键盘的方法。这是一个在按下特殊键序列时访问的子例程，比如*Ctrl* + *C*。

这是使用陷阱的一个例子：

## 第五章-脚本 7

```
#!/bin/sh
#
# 5/16/2017
#
echo "script7 - Linux Scripting Book"

trap catchCtrlC INT          # Initialize the trap

# Subroutines
catchCtrlC()
{
 echo "Entering catchCtrlC routine."
}

# Code starts here

echo "Press Ctrl-C to trigger the trap, 'Q' to exit."

loop=0
while [ $loop -eq 0 ]
do
 read -t 1 -n 1 str          # wait 1 sec for input or for 1 char
 rc=$?

 if [ $rc -gt 128 ] ; then
  echo "Timeout exceeded."
 fi

 if [ "$str" = "Q" ] ; then
  echo "Exiting the script."
  loop=1
 fi

done

exit 0
```

这是我系统上的输出：

![第五章-脚本 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_06.jpg)

在你的系统上运行这个脚本。按一些键，看看反应。也按几次*Ctrl* + *C*。完成后按*Q*。

那个`read`语句需要进一步解释。使用带有`-t`选项（超时）的`read`意味着等待那么多秒钟的字符。如果在规定的时间内没有输入字符，它将返回一个值大于 128 的代码。正如我们之前看到的，`-n 1`选项告诉`read`等待 1 个字符。这意味着我们等待 1 秒钟来输入 1 个字符。这是`read`可以用来创建游戏或其他交互式脚本的另一种方式。

### 注意

使用陷阱是捕捉意外按下*Ctrl* + *C*的好方法，这可能会导致数据丢失。然而，需要注意的是，如果你决定捕捉*Ctrl* + *C*，请确保你的脚本有其他退出方式。在上面的简单脚本中，用户必须输入“Q”才能退出。

如果你陷入无法退出脚本的情况，可以使用`kill`命令。

例如，如果我需要停止`script7`，指示如下：

```
 guest1 $ ps auxw | grep script7
 guest1   17813  0.0  0.0 106112  1252 pts/32   S+   17:23   0:00 /bin/sh ./script7
 guest1   17900  0.0  0.0 103316   864 pts/18   S+   17:23   0:00 grep script7
 guest1   29880  0.0  0.0  10752  1148 pts/17   S+   16:47   0:00 kw script7
 guest1 $ kill -9 17813
 guest1 $
```

在运行`script7`的终端上，你会看到它停在那里，并显示`Killed`。

请注意，一定要终止正确的进程！

在上面的例子中，PID`29880`是我正在写`script7`的文本编辑器会话。杀死它不是一个好主意：）。

现在来点乐趣！下一个脚本允许你在屏幕上画粗糙的图片：

## 第五章-脚本 8

```
#!/bin/sh
#
# 5/16/2017
#
echo "script8 - Linux Scripting Book"

# Subroutines
cls()
{
 tput clear
}

move()                       # move cursor to row, col
{
 tput cup $1 $2
}

movestr()                    # move cursor to row, col
{
 tput cup $1 $2
 echo -n "$3"                # display string
}

init()                       # set initial values
{
 minrow=1                    # terminal boundaries
 maxrow=24
 mincol=0
 maxcol=79
 startrow=1
 startcol=0
}

restart()                    # clears screen, sets initial cursor position
{
 cls
 movestr 0 0 "Arrow keys move cursor. 'x' to draw, 'd' to erase, '+' to restart, 'Q' to quit."
 row=$startrow
 col=$startcol

 draw=0                      # default is not drawing
 drawchar=""
}

checktermsize2()             # must be the specified size
{
 rc1=0                       # default is no error
 if [[ $LINES -ne $1 || $COLUMNS -ne $2 ]] ; then
  rc1=1                      # set return code
 fi
 return $rc1
}

# Code starts here
if [ "$1" = "--help" ] ; then
 echo "Usage: script7 --help"
 echo " This script shows the basics on how to create a game."
 echo " Use the arrow keys to move the cursor."
 echo " Press c to restart and Q to quit."
 exit 255
fi

checktermsize2 25 80         # terminal must be this size
rc=$?
if [ $rc -ne 0 ] ; then
 echo "Please size the terminal to 25x80 and try again."
 exit 1
fi

init                         # initialize values
restart                      # set starting cursor pos and clear screen

loop=1
while [ $loop -eq 1 ]
do
 move $row $col              # position the cursor here
 read -n 1 -s ch

 case "$ch" in
  A) if [ $row -gt $minrow ] ; then
      let row--
     fi
     ;;
  B) if [ $row -lt $maxrow ] ; then
      let row++
     fi
     ;;
  C) if [ $col -lt $maxcol ] ; then
      let col++
     fi
     ;;
  D) if [ $col -gt $mincol ] ; then
      let col--
     fi
     ;;
  d) echo -n ""             # delete char
     ;;
  x) if [ $col -lt $maxcol ] ; then
      echo -n "X"            # put char
      let col++
     fi
     ;;
  +) restart ;;
  Q) loop=0 ;;
 esac
done

movestr 24 0 "Script completed normally."
echo ""                      # carriage return

exit 0
```

写这个脚本很有趣，比我预期的更有趣一些。

我们还没有涉及的一件事是`case`语句。这类似于`if...then...else`，但使代码更易读。基本上，检查输入到`read`语句的值是否与每个`case`子句中的匹配。如果匹配，那个部分就会被执行，然后控制转到`esac`语句后的行。如果没有匹配，它也会这样做。

尝试这个脚本，并记住将终端设置为 25x80（或者如果你的 GUI 是这样工作的，80x25）。

这只是这个脚本可以做的一个例子：

![第五章-脚本 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_05_07.jpg)

好吧，我想这表明我不是一个很好的艺术家。我会继续从事编程和写书。

# 总结

在本章中，我们展示了如何使用`read`内置命令来查询键盘。我们解释了一些不同的读取选项，并介绍了陷阱的使用。还包括了一个简单的绘图游戏。

下一章将展示如何自动运行脚本，使其可以无人值守地运行。我们将解释如何使用`cron`在特定时间运行脚本。还将介绍归档程序`zip`和`tar`，因为它们在创建自动化备份脚本时非常有用。


# 第六章：使用脚本自动化任务

本章介绍了如何使用脚本自动化各种任务。

本章涵盖的主题如下：

+   如何创建一个自动化任务的脚本。

+   使用 cron 在特定时间自动运行脚本的正确方法。

+   如何使用`ZIP`和`TAR`进行压缩备份。

+   源代码示例。

读者将学习如何创建自动化脚本。

我们在第三章*使用循环和 sleep 命令*中谈到了`sleep`命令。只要遵循一些准则，它可以用来创建一个自动化脚本（即在特定时间运行而无需用户干预），。

这个非常简单的脚本将强化我们在第三章*使用循环和 sleep 命令*中所讨论的关于使用`sleep`命令进行自动化的内容：

# 第六章 - 脚本 1

```
#!/bin/sh
#
# 5/23/2017
#
echo "script1 - Linux Scripting Book"
while [ true ]
do
  date
  sleep 1d
done
echo "End of script1"
exit 0
```

如果你在你的系统上运行它并等几天，你会发现日期会有所偏移。这是因为`sleep`命令在脚本中插入了延迟，这并不意味着它会每天在同一时间运行脚本。

### 注意

以下脚本更详细地展示了这个问题。请注意，这是一个不应该做的例子。

## 第六章 - 脚本 2

```
#!/bin/sh
#
# 5/23/2017
#
echo "script2 - Linux Scripting Book"
while [ true ]
do
 # Run at 3 am
 date | grep -q 03:00:
 rc=$?
 if [ $rc -eq 0 ] ; then
  echo "Run commands here."
  date
 fi
 sleep 60                   # sleep 60 seconds
done
echo "End of script2"
exit 0
```

你会注意到的第一件事是，这个脚本会一直运行，直到它被手动终止，或者使用`kill`命令终止（或者机器因为任何原因而关闭）。自动化脚本通常会一直运行。

`date`命令在没有任何参数的情况下返回类似这样的东西：

```
  guest1 $ date
  Fri May 19 15:11:54 HST 2017
```

现在我们只需要使用`grep`来匹配那个时间。不幸的是，这里有一个非常微妙的问题。已经验证可能会偶尔漏掉。例如，如果时间刚刚变成凌晨 3 点，程序现在在休眠中，当它醒来时可能已经是 3:01 了。在我早期的计算机工作中，我经常看到这样的代码，从来没有想过。当有一天重要的备份被错过时，我的团队被要求找出问题所在，我们发现了这个问题。一个快速的解决方法是将秒数改为 59，但更好的方法是使用 cron，这将在本章后面展示。

注意`grep`的`-q`选项，这只是告诉它抑制任何输出。如果你愿意，可以在编写脚本时去掉这个选项。还要注意，`grep`在找到匹配时返回`0`，否则返回非零值。

说了这么多，让我们来看一些简单的自动化脚本。我从 1996 年开始在我的 Linux 系统上运行以下脚本：

## 第六章 - 脚本 3

```
#!/bin/sh
#
# 5/23/2017
#
echo "script3 - Linux Scripting Book"
FN=/tmp/log1.txt             # log file
while [ true ]
do
  echo Pinging $PROVIDER
  ping -c 1 $PROVIDER
  rc=$?
  if [ $rc -ne 0 ] ; then
    echo Cannot ping $PROVIDER
    date >> $FN
    echo Cannot ping $PROVIDER >> $FN
  fi
  sleep 60
done
echo "End of script3"        # 60 seconds
exit 0
```

以及在我的系统上的输出：

![第六章 - 脚本 3](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_06_01.jpg)

我只运行了三次，但它可以一直运行。在你的系统上运行之前，让我们谈谈`PROVIDER`环境变量。我的系统上有几个处理互联网的脚本，我发现自己不断地更改提供者。很快我意识到这是一个很好的时机来使用一个环境变量，因此是`PROVIDER`。

这是在我的`/root/.bashrc`和`/home/guest1/.bashrc`文件中的：

```
 export PROVIDER=twc.com
```

根据需要替换你自己的。还要注意，当发生故障时，它会被写入屏幕和文件中。由于使用了`>>`追加操作符，文件可能最终会变得相当大，所以如果你的连接不太稳定，要做好相应的计划。

### 提示

小心，不要在短时间内多次 ping 或以其他方式访问公司网站。这可能会被检测到，你的访问可能会被拒绝。

以下是一个脚本，用于检测用户何时登录或退出系统：

## 第六章 - 脚本 4

```
#!/bin/sh
#
# 5/23/2017
#
echo "Chapter 6 - Script 4"
numusers=`who | wc -l`
while [ true ]
do
  currusers=`who | wc -l`           # get current number of users
  if [ $currusers -gt $numusers ] ; then
    echo "Someone new has logged on!!!!!!!!!!!"
    date
    who
#   beep
    numusers=$currusers
  elif [ $currusers -lt $numusers ] ; then
    echo "Someone logged off."
    date
    numusers=$currusers
  fi
  sleep 1                    # sleep 1 second
done
```

以下是输出（根据长度调整）：

![第六章 - 脚本 4](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_06_02.jpg)

这个脚本检查 `who` 命令的输出，看看自上次运行以来是否有变化。如果有变化，它会采取适当的行动。如果你的系统上有 `beep` 命令或等效命令，这是一个很好的使用场景。

看一下这个陈述：

```
  currusers=`who | wc -l`           # get current number of users
```

这需要一些澄清，因为我们还没有涵盖它。那些反引号字符表示在其中运行命令，并将结果放入变量中。在这种情况下，`who` 命令被管道传递到 `wc -l` 命令中以计算行数。然后将这个值放入 `currusers` 变量中。如果这听起来有点复杂，不用担心，下一章将更详细地介绍。

脚本的其余部分应该已经很清楚了，因为我们之前已经涵盖过这部分。如果你决定在你的系统上运行类似的东西，只需记住，它将在每次打开新终端时触发。

## Cron

好了，现在来玩点真正的东西。即使你只是短时间使用 Linux，你可能已经意识到了 cron。这是一个守护进程，或者说是后台进程，它在特定的时间执行命令。

Cron 每分钟读取一个名为 `crontab` 的文件，以确定是否需要运行命令。

在本章的示例中，我们将只关注访客账户的 `crontab`（而不是 root 的）。

使用我的 `guest1` 账户，第一次运行时会是这个样子。在你的系统上以访客账户跟着做可能是个好主意：

```
guest1 $ crontab -l
no crontab for guest1
guest1 $
```

这是有道理的，因为我们还没有为 `guest1` 创建 `crontab` 文件。它不是用来直接编辑的，所以使用 `crontab -e` 命令。

现在在你的系统上以访客账户运行 `crontab -e`。

这是我在使用 vi 时在我的系统上的样子的屏幕截图：

![Cron](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_06_03.jpg)

正如你所看到的，`crontab` 命令创建了一个临时文件。不幸的是，这个文件是空的，因为他们应该提供一个模板。现在让我们添加一个。将以下文本复制并粘贴到文件中：

```
# this is the crontab file for guest1
# min   hour   day of month  month  day of week       command
# 0-59  0-23    1-31          1-12   0-6
#                                    Sun=0 Mon=1 Tue=2 Wed=3 Thu=4 Fri=5 Sat=6
```

将 `guest1` 替换为你的用户名。现在我们知道了应该放在哪里。

在这个文件中添加以下行：

```
  *     *      *      *      *                 date > /dev/pts/31
```

`*` 表示匹配字段中的所有内容。因此，这行实际上每分钟触发一次。

我们使用重定向运算符将 `echo` 命令的输出写入另一个终端。根据需要替换你自己的。

在你的系统上尝试上述操作。记住，你必须先保存文件，然后你应该看到这个输出：

```
guest1 $ crontab -e
crontab: installing new crontab
guest1 $
```

这意味着添加成功了。现在等待下一分钟到来。你应该在另一个终端看到当前日期显示出来。

现在我们可以看到 cron 的基础知识。以下是一些快速提示：

```
0   0    *   *   *   command            # run every day at midnight
0   3    *   *   *   command            # run every day at 3 am
30  9    1   *   *   command            # run at 9:30 am on the first of the month
45  14   *   *   0   command            # run at 2:45 pm on Sundays
0   0    25  12  *   command            # run at midnight on my birthday
```

这只是 cron 中日期和时间设置的一个非常小的子集。要了解更多信息，请参考 cron 和 `crontab` 的 `man` 页面。

需要提到的一件事是用户的 cron 的 `PATH`。它不会源自用户的 `.bashrc` 文件。你可以通过添加以下行来验证这一点：

```
*   *    *   *   *   echo $PATH > /dev/pts/31    # check the PATH
```

在我的 CentOS 6.8 系统上显示为：

```
/usr/bin:/bin
```

为了解决这个问题，你可以源自你的 `.bashrc` 文件：

```
*   *    *   *   *    source $HOME/.bashrc;  echo $PATH > /dev/pts/31    # check the PATH
```

现在应该显示真实路径。`EDITOR` 环境变量在第二章中提到，*变量处理*。如果你想让 `crontab` 使用不同的文本编辑器，你可以将 `EDITOR` 设置为你想要的路径/名称。

例如，在我的系统上，我有这个：

```
export EDITOR=/home/guest1/bin/kw
```

当我运行 `crontab -e` 时，我得到这个：

![Cron](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_06_04.jpg)

还有一件事需要提到的是，如果在使用 `crontab` 时出现错误，有些情况下它会在你尝试保存文件时告诉你。但它无法检查所有内容，所以要小心。此外，如果一个命令出现错误，`crontab` 将使用邮件系统通知用户。因此，记住这一点，当使用 cron 时，你可能需要不时地运行 `mail` 命令。

现在我们已经了解了基础知识，让我们创建一个使用`zip`命令的备份脚本。如果你不熟悉`zip`，不用担心，这会让你迅速掌握。在 Linux 系统上，大多数人只使用`tar`命令，然而，如果你知道`zip`的工作原理，你可以更容易地与 Windows 用户共享文件。

在一个访客账户的目录下，在你的系统上运行这些命令。像往常一样，我使用了`/home/guest1/LinuxScriptingBook`：

创建一个`work`目录：

```
guest1 ~/LinuxScriptingBook $ mkdir work
```

切换到它：

```
guest1 ~/LinuxScriptingBook $ cd work
```

创建一些临时文件，和/或将一些现有文件复制到这个目录：

```
guest1 ~/LinuxScriptingBook/work $ route > route.txt
guest1 ~/LinuxScriptingBook/work $ ifconfig > ifconfig.txt
guest1 ~/LinuxScriptingBook/work $ ls -la /usr > usr.txt
guest1 ~/LinuxScriptingBook/work $ cp /etc/motd .      
```

获取一个列表：

```
guest1 ~/LinuxScriptingBook/work $ ls -la
total 24
drwxrwxr-x 2 guest1 guest1 4096 May 23 09:44 .
drwxr-xr-x 8 guest1 guest1 4096 May 22 15:18 ..
-rw-rw-r-- 1 guest1 guest1 1732 May 23 09:44 ifconfig.txt
-rw-r--r-- 1 guest1 guest1 1227 May 23 09:44 motd
-rw-rw-r-- 1 guest1 guest1  335 May 23 09:44 route.txt
-rw-rw-r-- 1 guest1 guest1  724 May 23 09:44 usr.txt
```

把它们压缩起来：

```
guest1 ~/LinuxScriptingBook/work $ zip work1.zip *
  adding: ifconfig.txt (deflated 69%)
  adding: motd (deflated 49%)
  adding: route.txt (deflated 52%)
  adding: usr.txt (deflated 66%)
```

再获取一个列表：

```
guest1 ~/LinuxScriptingBook/work $ ls -la
total 28
drwxrwxr-x 2 guest1 guest1 4096 May 23 09:45 .
drwxr-xr-x 8 guest1 guest1 4096 May 22 15:18 ..
-rw-rw-r-- 1 guest1 guest1 1732 May 23 09:44 ifconfig.txt
-rw-r--r-- 1 guest1 guest1 1227 May 23 09:44 motd
-rw-rw-r-- 1 guest1 guest1  335 May 23 09:44 route.txt
-rw-rw-r-- 1 guest1 guest1  724 May 23 09:44 usr.txt
-rw-rw-r-- 1 guest1 guest1 2172 May 23 09:45 work1.zip
```

现在在那个目录中有一个名为`work1.zip`的文件。创建`zip`文件的语法是：

```
 zip [optional parameters] filename.zip list-of-files-to-include
```

要解压缩它：

```
 unzip filename.zip
```

要查看（或列出）`zip`文件的内容而不解压缩它：

```
 unzip -l filename.zip
```

这也是确保`.zip`文件正确创建的好方法，因为如果无法读取文件，解压缩会报错。请注意，`zip`命令不仅创建了一个`.zip`文件，还压缩了数据。这样可以生成更小的备份文件。 

这是一个使用`zip`备份一些文件的简短脚本：

## 第六章 - 脚本 5

```
#!/bin/sh
#
# 5/23/2017
#
echo "script5 - Linux Scripting Book"
FN=work1.zip
cd /tmp
mkdir work 2> /dev/null      # suppress message if directory already exists
cd work
cp /etc/motd .
cp /etc/issue .
ls -la /tmp > tmp.txt
ls -la /usr > usr.txt
rm $FN 2> /dev/null          # remove any previous file
zip $FN *
echo File "$FN" created.
# cp to an external drive, and/or scp to another computer
echo "End of script5"
exit 0
```

在我的系统上的输出：

![第六章 - 脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_06_05.jpg)

这是一个非常简单的脚本，但它展示了使用`zip`命令备份一些文件的基础知识。

假设我们想每天在午夜运行这个命令。假设`script5`位于`/tmp`下，`crontab`的条目将如下：

```
guest1 /tmp/work $ crontab -l
# this is the crontab file for guest1

# min   hour   day of month  month  day of week       command
# 0-59  0-23    1-31          1-12   0-6  Sun=0
#                                Sun=0 Mon=1 Tue=2 Wed=3 Thu=4 Fri=5 Sat=6

0 0 * * * /tmp/script5
```

在这种情况下，我们不需要源`/home/guest1/.bashrc`文件。还要注意，任何错误都会发送到用户的邮件账户。`zip`命令不仅可以做到这一点，例如它可以递归到目录中。要了解更多信息，请参考 man 手册。

现在让我们谈谈 Linux 的`tar`命令。它比`zip`命令更常用，更擅长获取所有文件，甚至是隐藏的文件。回到`/tmp/work`目录，这是你如何使用`tar`来备份它的。假设文件仍然存在于上一个脚本中：

```
guest1 /tmp $ tar cvzf work1.gz work/
work/
work/motd
work/tmp.txt
work/issue
work/work1.zip
work/usr.txt
guest1 /tmp $
```

现在在`/tmp`目录下有一个名为`work1.gz`的文件。它是`/tmp/work`目录下所有文件的压缩存档，包括我们之前创建的`.zip`文件。

tar 的语法一开始可能有点晦涩，但你会习惯的。tar 中可用的一些功能包括：

| 参数 | 特性 |
| --- | --- |
| `c` | 创建一个归档 |
| `x` | 提取一个归档 |
| `v` | 使用详细选项 |
| `z` | 使用 gunzip 风格的压缩（.gz） |
| `f` | 要创建/提取的文件名 |

请注意，如果不包括`z`选项，文件将不会被压缩。按照惯例，文件扩展名将只是 tar。请注意，用户控制文件的实际名称，而不是`tar`命令。

好了，现在我们有一个压缩的`tar-gz 文件`（或存档）。这是如何解压缩和提取文件的方法。我们将在`/home/guest1`下进行操作：

```
guest1 /home/guest1 $ tar xvzf /tmp/work1.gz
work/
work/motd
work/tmp.txt
work/issue
work/work1.zip
work/usr.txt
guest1 /home/guest1 $
```

使用 tar 备份系统真的很方便。这也是配置新机器使用你的个人文件的好方法。例如，我经常备份主系统上的以下目录：

```
 /home/guest1
 /lewis
 /temp
 /root
```

这些文件然后自动复制到外部 USB 驱动器。请记住，tar 会自动递归到目录中，并获取每个文件，包括隐藏的文件。Tar 还有许多其他选项，可以控制如何创建存档。最常见的选项之一是排除某些目录。

例如，当备份`/home/guest1`时，真的没有理由包括`.cache`、`Cache`、`.thumbnails`等目录。

排除目录的选项是`--exclude=<目录名>`，在下一个脚本中显示。

以下是我在主要 Linux 系统上使用的备份程序。这是两个脚本，一个用于安排备份，另一个用于实际执行工作。我主要是这样做的，以便我可以对实际备份脚本进行更改而不关闭调度程序脚本。需要设置的第一件事是`crontab`条目。这是我系统上的样子：

```
guest1 $ crontab -l
# this is the crontab file for guest1
# min   hour   day of month  month  day of week       command
# 0-59  0-23    1-31          1-12   0-6  Sun=0
#                                Sun=0 Mon=1 Tue=2 Wed=3 Thu=4 Fri=5 Sat=6
TTY=/dev/pts/31

 0  3   *  *  *  touch /tmp/runbackup-cron.txt
```

这将在每天凌晨 3 点左右创建文件`/tmp/backup-cron.txt`。

请注意，以下脚本必须以 root 身份运行：

## 第六章-脚本 6

```
#!/bin/sh
#
# runbackup1 - this version watches for file from crontab
#
# 6/3/2017 - mainlogs now under /data/mainlogs
#
VER="runbackup1 6/4/2017 A"
FN=/tmp/runbackup-cron.txt
DR=/wd1                      # symbolic link to external drive

tput clear
echo $VER

# Insure backup drive is mounted
file $DR | grep broken
rc=$?
if [ $rc -eq 0  ] ; then
 echo "ERROR: USB drive $DR is not mounted!!!!!!!!!!!!!!"
 beep
 exit 255
fi

cd $LDIR/backup

while [ true ]
do
 # crontab creates the file at 3 am

 if [ -f $FN ] ; then
  rm $FN
  echo Running backup1 ...
  backup1 | tee /data/mainlogs/mainlog`date '+%Y%m%d'`.txt
  echo $VER
 fi

 sleep 60                    # check every minute
done
```

这里有很多信息，所以我们将逐行进行解释：

+   脚本首先设置变量，清除屏幕，并显示脚本的名称。

+   `DR`变量分配给我的 USB 外部驱动器（`wd1`），它是一个符号链接。

+   然后使用`file`命令执行检查，以确保`/wd1`已挂载。如果没有，`file`命令将返回损坏的符号链接，`grep`将触发此操作，脚本将中止。

+   如果驱动器已挂载，则进入循环。每分钟检查文件的存在以查看是否是开始备份的时间。

+   找到文件后，将运行`backup1`脚本（见下文）。它的输出将使用`tee`命令发送到屏幕和文件。

+   日期格式说明符`'+%Y%m%d'`以 YYYYMMDD 格式显示日期

我不时检查`/data/mainlogs`目录中的文件，以确保我的备份正确创建且没有错误。

以下脚本用于备份我的系统。这里的逻辑是当前的每日备份存储在`$TDIR`目录中的硬盘上。它们也被复制到外部驱动器上的编号目录中。这些目录从 1 到 7 编号。当达到最后一个时，它会重新从 1 开始。这样，外部驱动器上始终有 7 天的备份可用。

此脚本也必须以 root 身份运行：

## 第六章-脚本 7

```
#!/bin/sh
#   Jim's backup program
#   Runs standalone
#   Copies to /data/backups first, then to USB backup drive
VER="File backup by Jim Lewis 5/27/2017 A"
TDIR=/data/backups
RUNDIR=$LDIR/backup
DR=/wd1
echo $VER
cd $RUNDIR
# Insure backup drive is mounted
file $DR | grep broken
a=$?
if [ "$a" != "1" ] ; then
 echo "ERROR: USB drive $DR is not mounted!!!!!!!!!!!!!!"
 beep
 exit 255
fi
date >> datelog.txt
date
echo "Removing files from $TDIR"
cd "$TDIR"
rc=$?
if [ $rc -ne 0 ] ; then
 echo "backup1: Error cannot change to $TDIR!"
 exit 250
fi
rm *.gz
echo "Backing up files to $TDIR"
X=`date '+%Y%m%d'`
cd /
tar cvzf "$TDIR/lewis$X.gz"  lewis
tar cvzf "$TDIR/temp$X.gz"   temp
tar cvzf "$TDIR/root$X.gz"   root
cd /home
tar cvzf "$TDIR/guest$X.gz" --exclude=Cache --exclude=.cache --exclude=.evolution --exclude=vmware --exclude=.thumbnails  --exclude=.gconf --exclude=.kde --exclude=.adobe  --exclude=.mozilla  --exclude=.gconf  --exclude=thunderbird  --exclude=.local --exclude=.macromedia  --exclude=.config   guest1
cd $RUNDIR
T=`cat filenum1`
BACKDIR=$DR/backups/$T
rm $BACKDIR/*.gz
cd "$TDIR"
cp *.gz $BACKDIR
echo $VER
cd $BACKDIR
pwd
ls -lah
cd $RUNDIR
let T++
if [ $T -gt 7 ] ; then
 T=1
fi
echo $T > filenum1
```

这比以前的脚本要复杂一些，所以让我们逐行进行解释：

+   `RUNDIR`变量保存脚本的起始目录。

+   `DR`变量指向外部备份驱动器。

+   检查驱动器以确保它已挂载。

+   当前日期被附加到`datelog.txt`文件。

+   `TDIR`变量是备份的目标目录。

+   执行`cd`到该目录并检查返回代码。出现错误时，脚本将以`250`退出。

+   删除前一天的备份。

现在它返回到`/`目录执行 tar 备份。

请注意，`guest1`目录中排除了几个目录。

+   `cd $RUNDIR`将其放回到起始目录。

+   `T=`filenum1``从该文件获取值并将其放入`T`变量中。这是用于在外部驱动器上下一个目录的计数器。

+   `BACKDIR`设置为旧备份，然后它们被删除。

+   控制再次返回到起始目录，并将当前备份复制到外部驱动器上的适当目录。

+   程序的版本再次显示，以便在杂乱的屏幕上轻松找到。

+   控制转到备份目录，`pwd`显示名称，然后显示目录的内容。

+   `T`变量递增 1。如果大于 7，则设置回 1。

最后，更新后的`T`变量被写回`filenum1`文件。

这个脚本应该作为您想要开发的任何备份过程的良好起点。请注意，`scp`命令可用于在没有用户干预的情况下直接将文件复制到另一台计算机。这将在第十章中介绍，*脚本最佳实践*。

# 总结

我们描述了如何创建一个脚本来自动化一个任务。我们讨论了如何使用 cron 在特定时间自动运行脚本的正确方法。我们讨论了存档命令`zip`和`tar`，以展示如何执行压缩备份。我们还包括并讨论了完整的调度程序和备份脚本。

在下一章中，我们将展示如何在脚本中读写文件。


# 第七章：文件操作

本章将展示如何从文本文件中读取和写入。它还将涵盖文件加密和校验和。

本章涵盖的主题如下：

+   展示如何使用重定向操作符写出文件

+   展示如何读取文件

+   解释如何捕获命令的输出并在脚本中使用

+   查看`cat`和其他重要命令

+   涵盖文件加密和校验和程序，如 sum 和 OpenSSL

# 写文件

我们在之前的一些章节中展示了如何使用重定向操作符创建和写入文件。简而言之，此命令将创建文件`ifconfig.txt`（或覆盖文件，如果文件已经存在）：

```
  ifconfig  >  ifconfig.txt
```

以下命令将追加到任何先前的文件，如果文件不存在，则创建一个新文件：

```
  ifconfig  >>  ifconfig.txt
```

之前的一些脚本使用反引号操作符从文件中检索数据。让我们通过查看*脚本 1*来回顾一下：

## 第七章-脚本 1

```
#!/bin/sh
#
# 6/1/2017
#
echo "Chapter 7 - Script 1"
FN=file1.txt
rm $FN 2> /dev/null          # remove it silently if it exists
x=1
while [ $x -le 10 ]          # 10 lines
do
 echo "x: $x"
 echo "Line $x" >> $FN       # append to file
 let x++
done
echo "End of script1"
exit 0
```

这是一个截图：

![第七章-脚本 1](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_01.jpg)

这很简单。如果文件存在，它会将文件（静默地）删除，然后输出每一行到文件，每次增加`x`。当`x`达到`10`时，循环终止。

# 读取文件

现在让我们再次看看上一章中备份脚本用于从文件中获取值的方法：

## 第七章-脚本 2

```
#!/bin/sh
#
# 6/2/2017
#
echo "Chapter 7 - Script 2"

FN=filenum1.txt              # input/output filename
MAXFILES=5                   # maximum number before going back to 1

if [ ! -f $FN ] ; then
  echo 1 > $FN               # create the file if it does not exist
fi

echo -n "Contents of $FN: "
cat $FN                      # display the contents

count=`cat $FN`              # put the output of cat into variable count
echo "Initial value of count from $FN: $count"

let count++
if [ $count -gt $MAXFILES ] ; then
 count=1
fi

echo "New value of count: $count"
echo $count > $FN

echo -n "New contents of $FN: "
cat $FN

echo "End of script2"
exit 0
```

这是*脚本 2*的截图：

![第七章-脚本 2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_02.jpg)

我们首先将`FN`变量设置为文件名（`filenum1.txt`）。它由`cat`命令显示，然后文件的内容被分配给`count`变量。它被显示，然后增加 1。新值被写回文件，然后再次显示。至少运行 6 次以查看其如何循环。

这只是创建和读取文件的一种简单方法。现在让我们看一个从文件中读取多行的脚本。它将使用前面*脚本 1*创建的文件`file1.txt`。

## 第七章-脚本 3

```
#!/bin/sh
#
# 6/1/2017
#
echo "Chapter 7 - Script 3"
FN=file1.txt                 # filename
while IFS= read -r linevar   # use read to put line into linevar
do
  echo "$linevar"            # display contents of linevar
done < $FN                   # the file to use as input
echo "End of script3"
exit 0
```

以下是输出：

![第七章-脚本 3](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_03.jpg)

这里的结构可能看起来有点奇怪，因为它与我们以前看到的非常不同。此脚本使用`read`命令获取文件的每一行。在语句中：

```
 while IFS= read -r linevar
```

`IFS=`（**内部字段分隔符**）防止`read`修剪前导和尾随的空白字符。`-r`参数使`read`忽略反斜杠转义序列。下一行使用重定向操作符，将`file1.txt`作为`read`的输入。

```
 done  <  $FN
```

这里有很多新材料，所以仔细查看，直到你对它感到舒适为止。

上面的脚本有一个小缺陷。如果文件不存在，将会出现错误。看看下面的截图：

![第七章-脚本 3](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_04.jpg)

Shell 脚本是解释性的，这意味着系统会逐行检查并运行。这与用 C 语言编写的程序不同，后者是经过编译的。这意味着任何语法错误都会在编译阶段出现，而不是在运行程序时出现。我们将在第九章“调试脚本”中讨论如何避免大多数 shell 脚本语法错误。

这是*脚本 4*，解决了缺少文件的问题：

## 第七章-脚本 4

```
#!/bin/sh
#
# 6/1/2017
#
echo "Chapter 7 - Script 4"

FN=file1.txt                 # filename
if [ ! -f $FN ] ; then
 echo "File $FN does not exist."
 exit 100
fi

while IFS= read -r linevar   # use read to put line into linevar
do
  echo "$linevar"            # display contents of linevar
done < $FN                   # the file to use as input

echo "End of script4"
exit 0
```

以下是输出：

![第七章-脚本 4](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_05.jpg)

在使用文件时请记住这一点，并始终检查文件是否存在，然后再尝试读取它。

# 读写文件

下一个脚本读取一个文本文件并创建其副本：

## 第七章-脚本 5

```
#!/bin/sh
#
# 6/1/2017
#
echo "Chapter 7 - Script 5"

if [ $# -ne 2 ] ; then
 echo "Usage: script5 infile outfile"
 echo " Copies text file infile to outfile."
 exit 255
fi

INFILE=$1
OUTFILE=$2

if [ ! -f $INFILE ] ; then
 echo "Error: File $INFILE does not exist."
 exit 100
fi

if [ $INFILE = $OUTFILE ] ; then
 echo "Error: Cannot copy to same file."
 exit 101
fi

rm $OUTFILE 2> /dev/null       # remove it
echo "Reading file $INFILE ..."

x=0
while IFS= read -r linevar     # use read to put line into linevar
do
  echo "$linevar" >> $OUTFILE  # append to file
  let x++
done < $INFILE                 # the file to use as input
echo "$x lines read."

diff $INFILE $OUTFILE          # use diff to check the output
rc=$?
if [ $rc -ne 0 ] ; then
 echo "Error, files do not match."
 exit 103
else
 echo "File $OUTFILE created."
fi

sum $INFILE $OUTFILE           # show the checksums

echo "End of script5"
exit $rc
```

这是*脚本 5*的截图：

![第七章-脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_06.jpg)

这展示了如何在脚本中读写文本文件。以下解释了每一行：

+   脚本开始时检查是否给出了两个参数，如果没有，则显示“用法”消息。

+   然后检查输入文件是否存在，如果不存在，则以代码`100`退出。

+   检查以确保用户没有尝试复制到相同的文件，因为在第 34 行可能会发生语法错误。这段代码确保不会发生这种情况。

+   如果输出文件存在，则删除它。这是因为我们想要复制到一个新文件，而不是追加到现有文件。

+   `while`循环读取和写入行。对`x`中行数进行计数。

+   循环结束时输出行数。

+   作为一个健全性检查，使用`diff`命令来确保文件是相同的。

+   并且作为额外的检查，对这两个文件运行`sum`命令。

# 交互式地读写文件

这个脚本与第五章中的一个类似，创建交互式脚本。它读取指定的文件，显示一个表单，并允许用户编辑然后保存它：

## 第七章-脚本 6

```
#!/bin/sh
# 6/2/2017
# Chapter 7 - Script 6

trap catchCtrlC INT          # Initialize the trap

# Subroutines
catchCtrlC()
{
 move 13 0
 savefile
 movestr 23 0 "Script terminated by user."
 echo ""                     # carriage return
 exit 0
}

cls()
{
 tput clear
}

move()                       # move cursor to row, col
{
 tput cup $1 $2
}

movestr()                    # move cursor to row, col
{
 tput cup $1 $2
 echo -n "$3"                # display string
}

checktermsize()
{
 rc1=0                       # default is no error
 if [[ $LINES -lt $1 || $COLUMNS -lt $2 ]] ; then
  rc1=1                      # set return code
 fi
 return $rc1
}

init()                       # set up the cursor position array
{
 srow[0]=2;  scol[0]=7       # name
 srow[1]=4;  scol[1]=12      # address 1
 srow[2]=6;  scol[2]=12      # address 2
 srow[3]=8;  scol[3]=7       # city
 srow[4]=8;  scol[4]=37      # state
 srow[5]=8;  scol[5]=52      # zip code
 srow[6]=10; scol[6]=8       # email
}

drawscreen()                 # main screen draw routine
{
 cls                         # clear the screen
 movestr 0 25 "Chapter 7 - Script 6"

 movestr 2 1  "Name: ${array[0]}"
 movestr 4 1  "Address 1: ${array[1]}"
 movestr 6 1  "Address 2: ${array[2]}"
 movestr 8 1  "City: ${array[3]}"
 movestr 8 30 "State: ${array[4]}"
 movestr 8 42 "Zip code: ${array[5]}"
 movestr 10 1 "Email: ${array[6]}"
}

getdata()
{
 x=0                         # start at the first field
 while [ true ]
 do
  row=${srow[x]}; col=${scol[x]}
  move $row $col
  read var
  if [ -n "$var" ] ; then    # if not blank assign to array
    array[$x]=$var
  fi
  let x++
  if [ $x -eq $sizeofarray ] ; then
   x=0                       # go back to first field
  fi
 done

 return 0
}

savefile()
{
 rm $FN 2> /dev/null         # remove any existing file
 echo "Writing file $FN ..."
 y=0
 while [ $y -lt $sizeofarray ]
 do
  echo "$y - '${array[$y]}'"            # display to screen
  echo "${array[$y]}" >> "$FN"          # write to file
  let y++
 done
 echo "File written."
 return 0
}

getfile()
{
 x=0
 if [ -n "$FN" ] ; then      # check that file exists
  while IFS= read -r linevar # use read to put line into linevar
  do
   array[$x]="$linevar"
   let x++
  done < $FN                 # the file to use as input
 fi
 return 0
}

# Code starts here
if [ $# -ne 1 ] ; then
 echo "Usage: script6 file"
 echo " Reads existing file or creates a new file"
 echo " and allows user to enter data into fields."
 echo " Press Ctrl-C to end."
 exit 255
fi

FN=$1                        # filename (input and output)
sizeofarray=7                # number of array elements
checktermsize 25 80
rc=$?
if [ $rc -ne 0 ] ; then
 echo "Please size the terminal to 25x80 and try again."
 exit 1
fi

init                         # initialize the screen array
getfile                      # read in file if it exists
drawscreen                   # draw the screen
getdata                      # read in the data and put into the fields

exit 0
```

在我的系统上是这样的：

![第七章-脚本 6](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_07.jpg)

这是代码的描述：

+   在这个脚本中设置的第一件事是一个*Ctrl* + *C*的陷阱，它会导致文件被保存并且脚本结束。

+   定义子例程。

+   使用`getdata`例程读取用户输入。

+   `savefile`例程写出数据数组。

+   `getfile`例程将文件（如果存在）读入数组。

+   检查参数，因为需要一个文件名。

+   将`FN`变量设置为文件的名称。

+   在使用数组时，最好有一个固定的大小，即`sizeofarray`。

+   检查终端的大小，确保它是 25x80（或 80x25，取决于你的 GUI）。

+   调用`init`例程设置屏幕数组。

+   调用`getfile`和`drawscreen`例程。

+   `getdata`例程用于移动光标并将字段中的数据放入正确的数组位置。

+   *Ctrl* + *C*用于保存文件并终止脚本。

这是一个简单的 Bash 屏幕输入/输出例程的示例。这个脚本可能需要一些改进，以下是部分列表：

+   检查现有文件是否有特定的头。这可以帮助确保文件格式正确，避免语法错误。

+   检查输入文件，确保它是文本而不是二进制。提示：使用`file`和`grep`命令。

+   如果文件无法正确写出，请确保优雅地捕获错误。

# 文件校验和

你可能注意到了上面使用了`sum`命令。它显示文件的校验和和块计数，可用于确定两个或更多个文件是否是相同的文件（即具有完全相同的内容）。

这是一个真实世界的例子：

假设你正在写一本书，文件正在从作者发送到出版商进行审阅。出版商进行了一些修订，然后将修订后的文件发送回作者。有时很容易出现不同步的情况，并收到一个看起来没有任何不同的文件。如果对这两个文件运行`sum`命令，你可以轻松地确定它们是否相同。

看一下下面的截图：

![文件校验和](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_08.jpg)

第一列是校验和，第二列是块计数。如果这两者都相同，那意味着文件的内容是相同的。所以，在这个例子中，bookfiles 1、2 和 4 是相同的。Bookfiles 3 和 5 也是相同的。然而，bookfiles 6、7 和 8 与任何文件都不匹配，最后两个甚至没有相同的块计数。

### 提示

注意：`sum`命令只查看文件的内容和块计数。它不查看文件名或其他文件属性，如所有权或权限。要做到这一点，你可以使用`ls`和`stat`命令。

# 文件加密

有时候你可能想要加密系统中一些重要和/或机密的文件。有些人把他们的密码存储在计算机的文件中，这可能没问题，但前提是要使用某种类型的文件加密。有许多加密程序可用，在这里我们将展示 OpenSSL。

OpenSSL 命令行工具非常流行，很可能已经安装在您的计算机上（它默认安装在我的 CentOS 6.8 系统上）。它有几个选项和加密方法，但我们只会涵盖基础知识。

再次使用上面的`file1.txt`在您的系统上尝试以下操作：

![文件加密](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_09.jpg)

我们首先对`file1.txt`文件执行求和，然后运行`openssl`。以下是语法：

+   `enc`：指定要使用的编码，在本例中是`aes-256-cbc`

+   `-in`：输入文件

+   `-out`：输出文件

+   `-d`：解密

运行`openssl`命令后，我们执行`ls -la`来验证输出文件是否确实已创建。

然后我们解密文件。请注意文件的顺序和添加`-d`参数（用于解密）。我们再次进行求和，以验证生成的文件与原始文件相同。

由于我不可能一直这样输入，让我们写一个快速脚本来做到这一点：

## 第七章-脚本 7

```
#!/bin/sh
#
# 6/2/2017
#
echo "Chapter 7 - Script 7"

if [ $# -ne 3 ] ; then
 echo "Usage: script7 -e|-d infile outfile"
 echo " Uses openssl to encrypt files."
 echo " -e to encrypt"
 echo " -d to decrypt"
 exit 255
fi

PARM=$1
INFILE=$2
OUTFILE=$3

if [ ! -f $INFILE ] ; then
 echo "Input file $INFILE does not exist."
 exit 100
fi

if [ "$PARM" = "-e" ] ; then
 echo "Encrypting"
 openssl enc -aes-256-cbc -in $INFILE -out $OUTFILE
elif [ "$PARM" = "-d" ] ; then
 echo "Decrypting"
 openssl enc -aes-256-cbc -d -in $INFILE -out $OUTFILE
else
 echo "Please specify either -e or -d."
 exit 101
fi

ls -la $OUTFILE

echo "End of script7"
exit 0
```

这是屏幕截图：

![第七章-脚本 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_07_10.jpg)

这显然比输入（或尝试记住）openssl 的语法要容易得多。正如您所看到的，解密后的文件（`file2.txt`）与`file1.txt`文件相同。

# 摘要

在本章中，我们展示了如何使用重定向运算符写出文件，以及如何使用（格式正确的）`read`命令读取文件。涵盖了将文件内容转换为变量的内容，以及使用校验和和文件加密。

在下一章中，我们将介绍一些可以用来从互联网上的网页收集信息的实用程序。


# 第八章：使用 wget 和 curl

本章将展示如何使用`wget`和`curl`直接从互联网上收集信息。

本章涵盖的主题有：

+   展示如何使用`wget`获取信息。

+   展示如何使用`curl`获取信息。

以这种方式收集数据的脚本可以是非常强大的工具。正如您从本章中所看到的，您可以从世界各地的网站自动获取股票报价、湖泊水位等等。

# 介绍 wget 程序

您可能已经听说过或者甚至使用过`wget`程序。它是一个命令行实用程序，可用于从互联网下载文件。

这里有一张截图显示了`wget`的最简单形式：

![介绍 wget 程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_01.jpg)

## wget 选项

在输出中，您可以看到`wget`从我的[jklewis.com](http://jklewis.com)网站下载了`index.html`文件。

这是`wget`的默认行为。标准用法是：

```
  wget [options] URL
```

其中**URL**代表**统一资源定位符**，或者网站的地址。

这里只是`wget`的许多可用选项的简短列表：

| 参数 | 解释 |
| --- | --- |
| `-o` | `log`文件，消息将被写入这里，而不是到`STDOUT` |
| `-a` | 与`-o`相同，除了它附加到`log`文件 |
| `-O` | 输出文件，将文件复制到这个名称 |
| `-d` | 打开调试 |
| `-q` | 静默模式 |
| `-v` | 详细模式 |
| `-r` | 递归模式 |

让我们试试另一个例子：

![wget 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_02.jpg)

在这种情况下使用了`-o`选项。检查了返回代码，代码`0`表示没有失败。没有输出，因为它被定向到`log`文件，然后由`cat`命令显示。

在这种情况下使用了`-o`选项，将输出写入文件。没有显示输出，因为它被定向到`log`文件，然后由`cat`命令显示。检查了`wget`的返回代码，代码`0`表示没有失败。

请注意，这次它将下载的文件命名为`index.html.1`。这是因为`index.html`是在上一个例子中创建的。这个应用程序的作者这样做是为了避免覆盖先前下载的文件。非常好！

看看下面的例子：

![wget 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_03.jpg)

在这里，我们告诉`wget`下载给定的文件（`shipfire.gif`）。

在下一个截图中，我们展示了`wget`如何返回一个有用的错误代码：

![wget 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_04.jpg)

## wget 返回代码

这个错误发生是因为在我的网站的基本目录中没有名为`shipfire100.gif`的文件。请注意输出显示了**404 Not Found**消息，这在网络上经常看到。一般来说，这意味着在那个时间点请求的资源不可用。在这种情况下，文件不存在，所以会出现这个消息。

还要注意`wget`如何返回了一个`8`错误代码。`wget`的 man 页面显示了可能的退出代码：

| 错误代码 | 解释 |
| --- | --- |
| `0` | 没有发生问题。 |
| `1` | 通用错误代码。 |
| `2` | 解析错误。例如在解析命令行选项时，`.wgetrc`或`.netrc`文件 |
| `3` | 文件 I/O 错误。 |
| `4` | 网络故障。 |
| `5` | SSL 验证失败。 |
| `6` | 用户名/密码验证失败。 |
| `7` | 协议错误。 |
| `8` | 服务器发出错误响应。 |

返回`8`是非常合理的。服务器找不到文件，因此返回了`404`错误代码。

## wget 配置文件

现在是时候提到不同的`wget`配置文件了。有两个主要文件，`/etc/wgetrc`是全局`wget`启动文件的默认位置。在大多数情况下，您可能不应该编辑这个文件，除非您真的想要进行影响所有用户的更改。文件`$HOME/.wgetrc`是放置任何您想要的选项的更好位置。一个好的方法是在文本编辑器中打开`/etc/wgetrc`和`$HOME/.wgetrc`，然后将您想要的部分复制到您的`$HOME./wgetrc`文件中。

有关`wget`配置文件的更多信息，请参阅`man`页面（`man wget`）。

现在让我们看看`wget`的运行情况。我写了这个脚本一段时间，以跟踪我曾经划船的湖泊的水位：

### 第八章-脚本 1

```
#!/bin/sh
# 6/5/2017
# Chapter 8 - Script 1

URL=http://www.arlut.utexas.edu/omg/weather.html
FN=weather.html
TF=temp1.txt                 # temp file
LF=logfile.txt               # log file

loop=1
while [ $loop -eq 1 ]
do
 rm $FN 2> /dev/null         # remove old file
 wget -o $LF $URL
 rc=$?
 if [ $rc -ne 0 ] ; then
  echo "wget returned code: $rc"
  echo "logfile:"
  cat $LF

  exit 200
 fi

 date
 grep "Lake Travis Level:" $FN > $TF
 cat $TF | cut  -d ' ' -f 12 --complement

 sleep 1h
done

exit 0
```

这个输出是从 2017 年 6 月 5 日。它看起来不怎么样，但在这里：

第八章-脚本 1

您可以从脚本和输出中看到，它每小时运行一次。如果您想知道为什么会有人写这样的东西，我需要知道湖泊水位是否低于 640 英尺，因为我必须把我的船移出码头。这是德克萨斯州的一次严重干旱期间。

编写这样的脚本时需要记住一些事情：

+   首次编写脚本时，手动执行`wget`一次，然后使用下载的文件进行操作。

+   不要在短时间内多次使用`wget`，否则您可能会被网站屏蔽。

+   请记住，HTML 程序员喜欢随时更改事物，因此您可能需要相应地调整您的脚本。

+   当您最终调整好脚本时，一定要再次激活`wget`。

# wget 和递归

`wget`程序还可以使用递归（`-r`）选项下载整个网站的内容。

例如，请查看以下屏幕截图：

![wget 和递归](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_06.jpg)

使用无冗长（`-nv`）选项来限制输出。`wget`命令完成后，使用 more 命令来查看日志的内容。根据文件数量，输出可能会非常长。

在使用`wget`时，您可能会遇到意外问题。它可能不会获取任何文件，或者可能获取其中一些但不是全部。它甚至可能在没有合理错误消息的情况下失败。如果发生这种情况，请非常仔细地查看`man`页面（`man wget`）。可能有一个选项可以帮助您解决问题。特别是要查看以下内容。

在您的系统上运行`wget --version`。它将显示选项和功能的详细列表，以及`wget`的编译方式。

以下是从我运行 CentOS 6.8 64 位系统中获取的示例：

![wget 和递归](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_07.jpg)

# wget 选项

通常情况下，`wget`的默认设置对大多数用户来说已经足够好，但是，您可能需要不时地进行调整，以使其按照您的意愿进行工作。

以下是一些`wget`选项的部分列表：

| wget 选项 | 解释 |
| --- | --- |
| --- | --- |
| `-o`文件名 | 将输出消息输出到`log`文件。这在本章中已经介绍过了。 |
| `-t`数字 | 在放弃连接之前尝试的次数。 |
| `-c` | 继续从以前的`wget`中下载部分下载的文件。 |
| `-S` | 显示服务器发送的标头。 |
| `-Q`数字 | 下载的总字节数配额。数字可以是字节，千字节（k）或兆字节（m）。设置为 0 或 inf 表示没有配额。 |
| `-l`数字 | 这指定了最大递归级别。默认值为 5。 |
| `-m` | 在尝试创建站点的镜像时很有用。相当于使用`-r -N -l inf --no-remove-listing`选项。 |

您可能尝试的另一件事是使用`-d`选项打开调试。请注意，这仅在您的`wget`版本编译时带有调试支持时才有效。让我们看看当我在我的系统上尝试时会发生什么：

![wget 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_08.jpg)

我不确定调试是否已打开，现在我知道了。这个输出可能不是很有用，除非你是开发人员，但是，如果你需要发送关于`wget`的错误报告，他们会要求调试输出。

正如你所看到的，`wget`是一个非常强大的程序，有许多选项。

### 注意

记得小心使用`wget`，不要忘记在循环中至少放一个睡眠。一个小时会更好。

# curl

现在让我们看一下`curl`程序，因为它与`wget`有些相似。`wget`和`curl`之间的主要区别之一是它们如何处理输出。

`wget`程序默认在屏幕上显示一些进度信息，然后下载`index.html`文件。相比之下，`curl`通常在屏幕上显示文件本身。

这是`curl`在我的系统上运行的一个例子，使用了我最喜欢的网站（截图缩短以节省空间）：

![curl](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_09.jpg)

将输出重定向到文件的另一种方法是使用重定向，就像这样：

![curl](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_10.jpg)

当重定向到文件时，你会注意到传输进度显示在屏幕上。还要注意，如果重定向了，任何错误输出都会进入文件而不是屏幕。

## curl 选项

这里是 curl 中可用选项的一个非常简要的列表：

| Curl 选项 | 说明 |
| --- | --- |
| `-o` | 输出文件名 |
| `-s` | 静默模式。什么都不显示，甚至错误也不显示 |
| `-S` | 在静默模式下显示错误 |
| `-v` | 详细模式，用于调试 |

`curl`还有许多其他选项，以及几页的返回代码。要了解更多信息，请参阅`curl man`页面。

现在这里有一个脚本，展示了如何使用 curl 自动获取道琼斯工业平均指数的当前值：

### 第八章-脚本 2

```
#!/bin/sh
# 6/6/2017
# Chapter 8 - Script 2

URL="https://www.google.com/finance?cid=983582"
FN=outfile1.txt              # output file
TF=temp1.txt                 # temp file for grep

loop=1
while [ $loop -eq 1 ]
do
 rm $FN 2> /dev/null         # remove old file
 curl -o $FN $URL            # output to file
 rc=$?
 if [ $rc -ne 0 ] ; then
  echo "curl returned code: $rc"
  echo "outfile:"
  cat $FN

  exit 200
 fi

 echo ""                     # carriage return
 date
 grep "ref_983582_l" $FN > $TF
 echo -n "DJIA: "
 cat $TF | cut -c 25-33

 sleep 1h
done

exit 0
```

这是在我的系统上的样子。通常情况下，你可能会使用`-s`选项将进度信息从输出中去掉，但我觉得它看起来很酷，所以留了下来：

![第八章-脚本 2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_08_11.jpg)

你可以看到`curl`和`wget`基本上是以相同的方式工作的。记住，当编写这样的脚本时，要牢记页面的格式几乎肯定会不时改变，所以要做好相应的计划。

# 总结

在本章中，我们展示了如何在脚本中使用`wget`和`curl`。展示了这些程序的默认行为，以及其中的许多选项。还讨论了返回代码，并呈现了一些示例脚本。 

以下章节将介绍如何更轻松地调试脚本中的语法和逻辑错误。
