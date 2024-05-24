# 精通 Linux 设备驱动开发（五）

> 原文：[`zh.annas-archive.org/md5/95A00CE7D8C2703D7FF8A1341D391E8B`](https://zh.annas-archive.org/md5/95A00CE7D8C2703D7FF8A1341D391E8B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：从用户空间利用 V4L2 API

设备驱动程序的主要目的是控制和利用底层硬件，同时向用户公开功能。这些用户可能是在用户空间运行的应用程序或其他内核驱动程序。前两章涉及 V4L2 设备驱动程序，而在本章中，我们将学习如何利用内核公开的 V4L2 设备功能。我们将首先描述和枚举用户空间 V4L2 API，然后学习如何利用这些 API 从传感器中获取视频数据，包括篡改传感器属性。

本章将涵盖以下主题：

+   V4L2 用户空间 API

+   视频设备属性管理从用户空间

+   用户空间的缓冲区管理

+   V4L2 用户空间工具

# 技术要求

为了充分利用本章，您将需要以下内容：

+   高级计算机体系结构知识和 C 编程技能

+   Linux 内核 v4.19.X 源代码，可在[`git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/refs/tags`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/refs/tags)获取

# 从用户空间介绍 V4L2

编写设备驱动程序的主要目的是简化应用程序对底层设备的控制和使用。用户空间处理 V4L2 设备有两种方式：一种是使用诸如`GStreamer`及其`gst-*`工具之类的一体化工具，另一种是使用用户空间 V4L2 API 编写专用应用程序。在本章中，我们只涉及代码，因此我们将介绍如何编写使用 V4L2 API 的应用程序。

## V4L2 用户空间 API

V4L2 用户空间 API 具有较少的功能和大量的数据结构，所有这些都在`include/uapi/linux/videodev2.h`中定义。在本节中，我们将尝试描述其中最重要的，或者更确切地说，最常用的。您的代码应包括以下标头：

```
#include <linux/videodev2.h>
```

此 API 依赖以下功能：

+   `open()`: 打开视频设备

+   `close()`: 关闭视频设备

+   `ioctl()`: 向显示驱动程序发送 ioctl 命令

+   `mmap()`: 将驱动程序分配的缓冲区内存映射到用户空间

+   `read()`或`write()`，取决于流方法

这个减少的 API 集合由大量的 ioctl 命令扩展，其中最重要的是：

+   `VIDIOC_QUERYCAP`: 用于查询驱动程序的功能。人们过去常说它用于查询设备的功能，但这并不正确，因为设备可能具有驱动程序中未实现的功能。用户空间传递一个`struct v4l2_capability`结构，该结构将由视频驱动程序填充相关信息。

+   `VIDIOC_ENUM_FMT`: 用于枚举驱动程序支持的图像格式。驱动程序用户空间传递一个`struct v4l2_fmtdesc`结构，该结构将由驱动程序填充相关信息。

+   `VIDIOC_G_FMT`: 对于捕获设备，用于获取当前图像格式。但是，对于显示设备，您可以使用此功能获取当前显示窗口。在任何情况下，用户空间传递一个`struct v4l2_format`结构，该结构将由驱动程序填充相关信息。

+   `VIDIOC_TRY_FMT`应在不确定要提交给设备的格式时使用。这用于验证捕获设备的新图像格式或根据输出（显示）设备使用新的显示窗口。用户空间传递一个带有它想要应用的属性的`struct v4l2_format`结构，如果它们不受支持，驱动程序可能会更改给定的值。然后应用程序应检查授予了什么。

+   `VIDIOC_S_FMT`用于为捕获设备设置新的图像格式或为显示（输出设备）设置新的显示窗口。如果不首先使用`VIDIOC_TRY_FMT`，驱动程序可能会更改用户空间传递的值，如果它们不受支持。应用程序应检查是否授予了什么。

+   `VIDIOC_CROPCAP` 用于根据当前图像大小和当前显示面板大小获取默认裁剪矩形。驱动程序填充一个 `struct v4l2_cropcap` 结构。

+   `VIDIOC_G_CROP` 用于获取当前裁剪矩形。驱动程序填充一个 `struct v4l2_crop` 结构。

+   `VIDIOC_S_CROP` 用于设置新的裁剪矩形。驱动程序填充一个 `struct v4l2_crop` 结构。应用程序应该检查授予了什么。

+   `VIDIOC_REQBUFS`：这个 ioctl 用于请求一定数量的缓冲区，以便稍后进行内存映射。驱动程序填充一个 `struct v4l2_requestbuffers` 结构。由于驱动程序可能分配的缓冲区数量多于或少于实际请求的数量，应用程序应该检查实际授予了多少个缓冲区。在此之后还没有排队任何缓冲区。

+   `VIDIOC_QUERYBUF` ioctl 用于获取缓冲区的信息，这些信息可以被 `mmap()` 系统调用用来将缓冲区映射到用户空间。驱动程序填充一个 `struct v4l2_buffer` 结构。

+   `VIDIOC_QBUF` 用于通过传递与该缓冲区相关联的 `struct v4l2_buffer` 结构来排队一个缓冲区。在这个 ioctl 的执行路径上，驱动程序将把这个缓冲区添加到其缓冲区列表中，以便在没有更多待处理的排队缓冲区之前填充它。一旦缓冲区被填充，它就会传递给 V4L2 核心，它维护自己的列表（即准备好的缓冲区列表），并且它会从驱动程序的 DMA 缓冲区列表中移除。

+   `VIDIOC_DQBUF` 用于从 V4L2 的准备好的缓冲区列表（对于输入设备）或显示的（输出设备）缓冲区中出列一个已填充的缓冲区，通过传递与该缓冲区相关联的 `struct v4l2_buffer` 结构。如果没有准备好的缓冲区，它会阻塞，除非在 `open()` 中使用了 `O_NONBLOCK`，在这种情况下，`VIDIOC_DQBUF` 会立即返回一个 `EAGAIN` 错误代码。只有在调用了 `STREAMON` 之后才应该调用 `VIDIOC_DQBUF`。与此同时，在 `STREAMOFF` 之后调用这个 ioctl 会返回 `-EINVAL`。

+   `VIDIOC_STREAMON` 用于开启流。之后，任何 `VIDIOC_QBUF` 的结果都会呈现图像。

+   `VIDIOC_STREAMOFF` 用于关闭流。这个 ioctl 移除所有缓冲区。它实际上刷新了缓冲队列。

有很多 ioctl 命令，不仅仅是我们刚刚列举的那些。实际上，内核的 `v4l2_ioctl_ops` 数据结构中至少有和操作一样多的 ioctl。然而，上述的 ioctl 已经足够深入了解 V4L2 用户空间 API。在本节中，我们不会详细介绍每个数据结构。因此，你应该保持 `include/uapi/linux/videodev2.h` 文件的打开状态，也可以在 [`elixir.bootlin.com/linux/v4.19/source/include/uapi/linux/videodev2.h`](https://elixir.bootlin.com/linux/v4.19/source/include/uapi/linux/videodev2.h) 找到，因为它包含了所有的 V4L2 API 和数据结构。话虽如此，以下伪代码展示了使用 V4L2 API 从用户空间抓取视频的典型 ioctl 序列：

```
open()
int ioctl(int fd, VIDIOC_QUERYCAP,           struct v4l2_capability *argp)
int ioctl(int fd, VIDIOC_S_FMT, struct v4l2_format *argp)
int ioctl(int fd, VIDIOC_S_FMT, struct v4l2_format *argp)
/* requesting N buffers */
int ioctl(int fd, VIDIOC_REQBUFS,           struct v4l2_requestbuffers *argp)
/* queueing N buffers */
int ioctl(int fd, VIDIOC_QBUF, struct v4l2_buffer *argp)
/* start streaming */
int ioctl(int fd, VIDIOC_STREAMON, const int *argp) 
read_loop: (for i=0; I < N; i++)
    /* Dequeue buffer i */
    int ioctl(int fd, VIDIOC_DQBUF, struct v4l2_buffer *argp)
    process_buffer(i)
    /* Requeue buffer i */
    int ioctl(int fd, VIDIOC_QBUF, struct v4l2_buffer *argp)
end_loop
    releases_memories()
    close()
```

上述序列将作为指南来处理用户空间中的 V4L2 API。

请注意，`ioctl` 系统调用可能返回 `-1` 值，而 `errno = EINTR`。在这种情况下，这并不意味着错误，而只是系统调用被中断，此时应该再次尝试。为了解决这个（虽然可能性很小但是可能发生的）问题，我们可以考虑编写自己的 `ioctl` 包装器，例如以下内容：

```
static int xioctl(int fh, int request, void *arg)
{
        int r;
        do {
                r = ioctl(fh, request, arg);
        } while (-1 == r && EINTR == errno);
        return r;
}
```

现在我们已经完成了视频抓取序列的概述，我们可以弄清楚从设备打开到关闭的视频流程需要哪些步骤，包括格式协商。现在我们可以跳转到代码，从设备打开开始，一切都从这里开始。

# 视频设备的打开和属性管理

驱动程序在`/dev/`目录中公开节点条目，对应于它们负责的视频接口。这些文件节点对应于捕获设备的`/dev/videoX`特殊文件（在我们的情况下）。应用程序必须在与视频设备的任何交互之前打开适当的文件节点。它使用`open()`系统调用来打开，这将返回一个文件描述符，将成为发送到设备的任何命令的入口点，如下例所示：

```
static const char *dev_name = "/dev/video0";
fd = open (dev_name, O_RDWR);
if (fd == -1) {
    perror("Failed to open capture device\n");
    return -1;
}
```

前面的片段是以阻塞模式打开的。将`O_NONBLOCK`传递给`open()`将防止应用程序在尝试出队时没有准备好的缓冲区时被阻塞。完成视频设备的使用后，应使用`close()`系统调用关闭它：

```
close (fd);
```

在我们能够打开视频设备之后，我们可以开始与其进行交互。通常，视频设备打开后发生的第一个动作是查询其功能，通过这个功能，我们可以使其以最佳方式运行。

## 查询设备功能

通常查询设备的功能以确保它支持我们需要处理的模式是很常见的。您可以使用`VIDIOC_QUERYCAP` ioctl 命令来执行此操作。为此，应用程序传递一个`struct v4l2_capability`结构（在`include/uapi/linux/videodev2.h`中定义），该结构将由驱动程序填充。该结构具有一个`.capabilities`字段需要进行检查。该字段包含整个设备的功能。内核源代码的以下摘录显示了可能的值：

```
/* Values for 'capabilities' field */
#define V4L2_CAP_VIDEO_CAPTURE 0x00000001 /*video capture device*/ #define V4L2_CAP_VIDEO_OUTPUT 0x00000002  /*video output device*/ #define V4L2_CAP_VIDEO_OVERLAY 0x00000004 /*Can do video overlay*/ [...] /* VBI device skipped */
/* video capture device that supports multiplanar formats */#define V4L2_CAP_VIDEO_CAPTURE_MPLANE	0x00001000
/* video output device that supports multiplanar formats */ #define V4L2_CAP_VIDEO_OUTPUT_MPLANE	0x00002000
/* mem-to-mem device that supports multiplanar formats */#define V4L2_CAP_VIDEO_M2M_MPLANE	0x00004000
/* Is a video mem-to-mem device */#define V4L2_CAP_VIDEO_M2M	0x00008000
[...] /* radio, tunner and sdr devices skipped */
#define V4L2_CAP_READWRITE	0x01000000 /*read/write systemcalls */ #define V4L2_CAP_ASYNCIO	0x02000000	/* async I/O */
#define V4L2_CAP_STREAMING	0x04000000	/* streaming I/O ioctls */ #define V4L2_CAP_TOUCH	0x10000000	/* Is a touch device */
```

以下代码块显示了一个常见用例，展示了如何使用`VIDIOC_QUERYCAP` ioctl 从代码中查询设备功能：

```
#include <linux/videodev2.h>
[...]
struct v4l2_capability cap;
memset(&cap, 0, sizeof(cap));
if (-1 == xioctl(fd, VIDIOC_QUERYCAP, &cap)) {
    if (EINVAL == errno) {
        fprintf(stderr, "%s is no V4L2 device\n", dev_name);
        exit(EXIT_FAILURE);
    } else {
        errno_exit("VIDIOC_QUERYCAP" 
    }
}
```

在前面的代码中，`struct v4l2_capability`在传递给`ioctl`命令之前首先通过`memset()`清零。在这一步，如果没有错误发生，那么我们的`cap`变量现在包含了设备的功能。您可以使用以下内容来检查设备类型和 I/O 方法：

```
if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
    fprintf(stderr, "%s is not a video capture device\n",             dev_name);
    exit(EXIT_FAILURE);
}
if (!(cap.capabilities & V4L2_CAP_READWRITE))
    fprintf(stderr, "%s does not support read i/o\n",             dev_name);
/* Check whether USERPTR and/or MMAP method are supported */
if (!(cap.capabilities & V4L2_CAP_STREAMING))
    fprintf(stderr, "%s does not support streaming i/o\n",             dev_name);
/* Check whether driver support read/write i/o */
if (!(cap.capabilities & V4L2_CAP_READWRITE))
    fprintf (stderr, "%s does not support read i/o\n",              dev_name);
```

您可能已经注意到，在使用之前，我们首先将`cap`变量清零。在给 V4L2 API 提供参数时，清除参数是一个好的做法，以避免陈旧的内容。然后，让我们定义一个宏——比如`CLEAR`——它将清零作为参数给定的任何变量，并在本章的其余部分中使用它：

```
#define CLEAR(x) memset(&(x), 0, sizeof(x))
```

现在，我们已经完成了查询视频设备功能。这使我们能够配置设备并根据我们需要实现的内容调整图像格式。通过协商适当的图像格式，我们可以利用视频设备，正如我们将在下一节中看到的那样。

# 缓冲区管理

在 V4L2 中，维护两个缓冲队列：一个用于驱动程序（称为`VIDIOC_QBUF` ioctl）。缓冲区按照它们被入队的顺序由驱动程序填充。一旦填充，每个缓冲区就会从输入队列移出，并放入输出队列，即用户队列。

每当用户应用程序调用`VIDIOC_DQBUF`以出队一个缓冲区时，该缓冲区将在输出队列中查找。如果在那里，缓冲区将被出队并*推送*到用户应用程序；否则，应用程序将等待直到有填充的缓冲区。用户完成使用缓冲区后，必须调用`VIDIOC_QBUF`将该缓冲区重新入队到输入队列中，以便可以再次填充。

驱动程序初始化后，应用程序调用`VIDIOC_REQBUFS` ioctl 来设置它需要处理的缓冲区数量。一旦获准，应用程序使用`VIDIOC_QBUF`队列中的所有缓冲区，然后调用`VIDIOC_STREAMON` ioctl。然后，驱动程序自行填充所有排队的缓冲区。如果没有更多排队的缓冲区，那么驱动程序将等待应用程序入队缓冲区。如果出现这种情况，那么这意味着在捕获本身中丢失了一些帧。

## 图像（缓冲区）格式

在确保设备是正确类型并支持其可以使用的模式之后，应用程序必须协商其需要的视频格式。应用程序必须确保视频设备配置为以应用程序可以处理的格式发送视频帧。在开始抓取和收集数据（或视频帧）之前，必须这样做。V4L2 API 使用`struct v4l2_format`来表示缓冲区格式，无论设备类型是什么。该结构定义如下：

```
struct v4l2_format {
 u32 type;
 union {
  struct v4l2_pix_format pix; /* V4L2_BUF_TYPE_VIDEO_CAPTURE */    
  struct v4l2_pix_format_mplane pix_mp; /* _CAPTURE_MPLANE */
  struct v4l2_window win;	 /* V4L2_BUF_TYPE_VIDEO_OVERLAY */
  struct v4l2_vbi_format vbi; /* V4L2_BUF_TYPE_VBI_CAPTURE */
  struct v4l2_sliced_vbi_format sliced;/*_SLICED_VBI_CAPTURE */ 
  struct v4l2_sdr_format sdr;   /* V4L2_BUF_TYPE_SDR_CAPTURE */
  struct v4l2_meta_format meta;/* V4L2_BUF_TYPE_META_CAPTURE */
        [...]
    } fmt;
};
```

在前面的结构中，`type`字段表示数据流的类型，并应由应用程序设置。根据其值，`fmt`字段将是适当的类型。在我们的情况下，`type`必须是`V4L2_BUF_TYPE_VIDEO_CAPTURE`，因为我们正在处理视频捕获设备。然后，`fmt`将是`struct v4l2_pix_format`类型。

重要说明

几乎所有（如果不是全部）直接或间接与缓冲区播放的 ioctl（如裁剪、缓冲区请求/排队/出队/查询）都需要指定缓冲区类型，这是有道理的。我们将使用`V4L2_BUF_TYPE_VIDEO_CAPTURE`，因为这是我们设备类型的唯一选择。缓冲区类型的整个列表是在`include/uapi/linux/videodev2.h`中定义的`enum v4l2_buf_type`类型。你应该看一看。

应用程序通常会查询视频设备的当前格式，然后仅更改其中感兴趣的属性，并将新的混合缓冲区格式发送回视频设备。但这并不是强制性的。我们只是在这里做了这个演示，以演示您如何获取或设置当前格式。应用程序使用`VIDIOC_G_FMT` ioctl 命令查询当前缓冲区格式。它必须传递一个新的（我指的是清零的）`struct v4l2_format`结构，并设置`type`字段。驱动程序将在 ioctl 的返回路径中填充其余部分。以下是一个例子：

```
struct v4l2_format fmt;
CLEAR(fmt);
/* Get the current format */
fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
if (ioctl(fd, VIDIOC_G_FMT, &fmt)) {
    printf("Getting format failed\n");
    exit(2);
}
```

一旦我们有了当前的格式，我们就可以更改相关属性，并将新格式发送回设备。这些属性可能是像素格式，每个颜色分量的内存组织，以及每个字段的交错捕获内存组织。我们还可以描述缓冲区的大小和间距。设备支持的常见（但不是唯一的）像素格式如下：

+   `V4L2_PIX_FMT_YUYV`：YUV422（交错）

+   `V4L2_PIX_FMT_NV12`：YUV420（半平面）

+   `V4L2_PIX_FMT_NV16`：YUV422（半平面）

+   `V4L2_PIX_FMT_RGB24`：RGB888（打包）

现在，让我们编写改变我们需要的属性的代码片段。但是，将新格式发送到视频设备需要使用新的 ioctl 命令，即`VIDIOC_S_FMT`：

```
#define WIDTH	1920
#define HEIGHT	1080
#define PIXFMT	V4L2_PIX_FMT_YUV420
/* Changing required properties and set the format */ fmt.fmt.pix.width = WIDTH;
fmt.fmt.pix.height = HEIGHT;
fmt.fmt.pix.bytesperline = fmt.fmt.pix.width * 2u;
fmt.fmt.pix.sizeimage = fmt.fmt.pix.bytesperline * fmt.fmt.pix.height; 
fmt.fmt.pix.colorspace = V4L2_COLORSPACE_REC709;
fmt.fmt.pix.field = V4L2_FIELD_ANY;
fmt.fmt.pix.pixelformat = PIXFMT;
fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
if (xioctl(fd, VIDIOC_S_FMT, &fmt)) {
    printf("Setting format failed\n");
    exit(2);
}
```

重要说明

我们可以使用前面的代码，而不需要当前格式。

ioctl 可能会成功。但是，这并不意味着您的参数已经被应用。默认情况下，设备可能不支持每种图像宽度和高度的组合，甚至不支持所需的像素格式。在这种情况下，驱动程序将应用其支持的最接近的值，以符合您请求的值。然后，您需要检查您的参数是否被接受，或者被授予的参数是否足够好，以便您继续进行：

```
if (fmt.fmt.pix.pixelformat != PIXFMT)
   printf("Driver didn't accept our format. Can't proceed.\n");
/* because VIDIOC_S_FMT may change width and height */
if ((fmt.fmt.pix.width != WIDTH) ||     (fmt.fmt.pix.height != HEIGHT))     
 fprintf(stderr, "Warning: driver is sending image at %dx%d\n",
            fmt.fmt.pix.width, fmt.fmt.pix.height);
```

我们甚至可以进一步改变流参数，例如每秒帧数。我们可以通过以下方式实现这一点：

+   使用`VIDIOC_G_PARM` ioctl 查询视频设备的流参数。此 ioctl 接受一个新的`struct v4l2_streamparm`结构作为参数，并设置其`type`成员。此类型应该是`enum v4l2_buf_type`值之一。

+   检查`v4l2_streamparm.parm.capture.capability`，并确保设置了`V4L2_CAP_TIMEPERFRAME`标志。这意味着驱动程序允许更改捕获帧速率。

如果是这样，我们可以（可选地）使用`VIDIOC_ENUM_FRAMEINTERVALS` ioctl 来获取可能的帧间隔列表（API 使用帧间隔，这是帧速率的倒数）。

+   使用`VIDIOC_S_PARM` ioctl 并填写`v4l2_streamparm.parm.capture.timeperframe`成员的适当值。这应该允许设置捕获端的帧速率。您的任务是确保您读取得足够快，以免出现帧丢失。

以下是一个例子：

```
#define FRAMERATE 30
struct v4l2_streamparm parm;
int error;
CLEAR(parm);
parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
/* first query streaming parameters */
error = xioctl(fd, VIDIOC_G_PARM, &parm);
if (!error) {
    /* Now determine if the FPS selection is supported */
    if (parm.parm.capture.capability & V4L2_CAP_TIMEPERFRAME) {
        /* yes we can */
        CLEAR(parm);
        parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        parm.parm.capture.capturemode = 0;
        parm.parm.capture.timeperframe.numerator = 1;
        parm.parm.capture.timeperframe.denominator = FRAMERATE;
        error = xioctl(fd, VIDIOC_S_PARM, &parm);
        if (error)
            printf("Unable to set the FPS\n");
        else
           /* once again, driver may have changed our requested 
            * framerate */
            if (FRAMERATE != 
                  parm.parm.capture.timeperframe.denominator)
                printf ("fps coerced ......: from %d to %d\n",
                        FRAMERATE,
                   parm.parm.capture.timeperframe.denominator);
```

现在，我们可以协商图像格式并设置流参数。下一个逻辑延续将是请求缓冲区并继续进行进一步处理。

## 请求缓冲区

完成格式准备后，现在是指示驱动程序分配用于存储视频帧的内存的时候了。`VIDIOC_REQBUFS` ioctl 就是为了实现这一点。此 ioctl 将新的`struct v4l2_requestbuffers`结构作为参数。在传递给 ioctl 之前，`v4l2_requestbuffers`必须设置其一些字段：

+   `v4l2_requestbuffers.count`：此成员应设置为要分配的内存缓冲区的数量。此成员应设置为确保帧不会因输入队列中排队的缓冲区不足而丢失的值。大多数情况下，`3`或`4`是正确的值。因此，驱动程序可能不满意请求的缓冲区数量。在这种情况下，驱动程序将在 ioctl 的返回路径上使用授予的缓冲区数量设置`v4l2_requestbuffers.count`。然后，应用程序应检查此值，以确保此授予的值符合其需求。

+   `v4l2_requestbuffers.type`：这必须使用`enum 4l2_buf_type`类型的视频缓冲区类型进行设置。在这里，我们再次使用`V4L2_BUF_TYPE_VIDEO_CAPTURE`。例如，对于输出设备，这将是`V4L2_BUF_TYPE_VIDEO_OUTPUT`。

+   `v4l2_requestbuffers.memory`：这必须是可能的`enum v4l2_memory`值之一。感兴趣的可能值是`V4L2_MEMORY_MMAP`，`V4L2_MEMORY_USERPTR`和`V4L2_MEMORY_DMABUF`。这些都是流式传输方法。但是，根据此成员的值，应用程序可能需要执行其他任务。不幸的是，`VIDIOC_REQBUFS`命令是应用程序发现给定驱动程序支持哪些类型的流式 I/O 缓冲区的唯一方法。然后，应用程序可以尝试使用这些值中的每一个`VIDIOC_REQBUFS`，并根据失败或成功的情况调整其逻辑。

### 请求用户指针缓冲区 - VIDIOC_REQBUFS 和 malloc

这一步涉及驱动程序支持流式传输模式，特别是用户指针 I/O 模式。在这里，应用程序通知驱动程序即将分配一定数量的缓冲区：

```
#define BUF_COUNT 4
struct v4l2_requestbuffers req; CLEAR (req);
req.count	= BUF_COUNT;
req.type	= V4L2_BUF_TYPE_VIDEO_CAPTURE;
req.memory	= V4L2_MEMORY_USERPTR;
if (-1 == xioctl (fd, VIDIOC_REQBUFS, &req)) {
    if (EINVAL == errno)
        fprintf(stderr,                 "%s does not support user pointer i/o\n", 
                dev_name);
    else
        fprintf("VIDIOC_REQBUFS failed \n");
}
```

然后，应用程序从用户空间分配缓冲区内存：

```
struct buffer_addr {
    void  *start;
    size_t length;
};
struct buffer_addr *buf_addr;
int i;
buf_addr = calloc(BUF_COUNT, sizeof (*buffer_addr));
if (!buf_addr) {
    fprintf(stderr, "Out of memory\n");
    exit (EXIT_FAILURE);
}
for (i = 0; i < BUF_COUNT; ++i) {
    buf_addr[i].length = buffer_size;
    buf_addr[i].start = malloc(buffer_size);
    if (!buf_addr[i].start) {
        fprintf(stderr, "Out of memory\n");
        exit(EXIT_FAILURE);
    }
}
```

这是第一种流式传输，其中缓冲区在用户空间中分配并交给内核以便填充视频数据：所谓的用户指针 I/O 模式。还有另一种花哨的流式传输模式，几乎所有操作都是从内核完成的。让我们立刻介绍它。

### 请求内存可映射缓冲区 - VIDIOC_REQBUFS，VIDIOC_QUERYBUF 和 mmap

在驱动程序缓冲区模式中，此 ioctl 还返回`v4l2_requestbuffer`结构的`count`成员中分配的实际缓冲区数量。此流式传输方法还需要一个新的数据结构`struct v4l2_buffer`。在内核中由驱动程序分配缓冲区后，此结构与`VIDIOC_QUERYBUFS` ioctl 一起使用，以查询每个分配的缓冲区的物理地址，该地址可与`mmap()`系统调用一起使用。驱动程序返回的物理地址将存储在`buffer.m.offset`中。

以下代码摘录指示驱动程序分配内存缓冲区并检查授予的缓冲区数量：

```
#define BUF_COUNT_MIN 3
struct v4l2_requestbuffers req; CLEAR (req);
req.count	= BUF_COUNT;
req.type	= V4L2_BUF_TYPE_VIDEO_CAPTURE;
req.memory	= V4L2_MEMORY_MMAP;
if (-1 == xioctl (fd, VIDIOC_REQBUFS, &req)) {
    if (EINVAL == errno)
        fprintf(stderr, "%s does not support memory mapping\n", 
                dev_name);
    else
        fprintf("VIDIOC_REQBUFS failed \n");
}
/* driver may have granted less than the number of buffers we
 * requested let's then make sure it is not less than the
 * minimum we can deal with
 */
if (req.count < BUF_COUNT_MIN) {
    fprintf(stderr, "Insufficient buffer memory on %s\n",             dev_name);
    exit (EXIT_FAILURE);
}
```

之后，应用程序应该对每个分配的缓冲区调用`VIDIOC_QUERYBUF` ioctl，以获取它们对应的物理地址，如下例所示：

```
struct buffer_addr {
    void *start;
    size_t length;
};
struct buffer_addr *buf_addr;
buf_addr = calloc(BUF_COUNT, sizeof (*buffer_addr));
if (!buf_addr) {
    fprintf (stderr, "Out of memory\n");
    exit (EXIT_FAILURE);
}
for (i = 0; i < req.count; ++i) {
    struct v4l2_buffer buf;
    CLEAR (buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP; buf.index	= i;
    if (-1 == xioctl (fd, VIDIOC_QUERYBUF, &buf))
        errno_exit("VIDIOC_QUERYBUF");
    buf_addr[i].length = buf.length;
    buf_addr[i].start =
        mmap (NULL /* start anywhere */, buf.length,
              PROT_READ | PROT_WRITE /* required */,
              MAP_SHARED /* recommended */, fd, buf.m.offset);
    if (MAP_FAILED == buf_addr[i].start)
        errno_exit("mmap");
}
```

为了使应用程序能够内部跟踪每个缓冲区的内存映射（使用`mmap()`获得），我们定义了一个自定义数据结构`struct buffer_addr`，为每个授予的缓冲区分配，该结构将保存与该缓冲区对应的映射。

### 请求 DMABUF 缓冲区 - VIDIOC_REQBUFS、VIDIOC_EXPBUF 和 mmap

DMABUF 主要用于`mem2mem`设备，并引入了**导出者**和**导入者**的概念。假设驱动程序**A**想要使用由驱动程序**B**创建的缓冲区；那么我们称**B**为导出者，**A**为缓冲区用户/导入者。

`export`方法指示驱动程序通过文件描述符将其 DMA 缓冲区导出到用户空间。应用程序使用`VIDIOC_EXPBUF` ioctl 来实现这一点，并需要一个新的数据结构`struct v4l2_exportbuffer`。在此 ioctl 的返回路径上，驱动程序将使用文件描述符设置`v4l2_requestbuffers.md`成员，该文件描述符对应于给定缓冲区。这是一个 DMABUF 文件描述符：

```
/* V4L2 DMABuf export */
struct v4l2_requestbuffers req;
CLEAR (req);
req.count = BUF_COUNT;
req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
req.memory = V4L2_MEMORY_DMABUF;
if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req))
    errno_exit ("VIDIOC_QUERYBUFS");
```

应用程序可以将这些缓冲区导出为 DMABUF 文件描述符，以便可以将其内存映射到访问捕获的视频内容。应用程序应该使用`VIDIOC_EXPBUF`ioctl 来实现这一点。此 ioctl 扩展了内存映射 I/O 方法，因此仅适用于`V4L2_MEMORY_MMAP`缓冲区。但是，使用`VIDIOC_EXPBUF`导出捕获缓冲区然后映射它们实际上是没有意义的。应该使用`V4L2_MEMORY_MMAP`。

`VIDIOC_EXPBUF`在涉及 V4L2 输出设备时变得非常有趣。这样，应用程序可以使用`VIDIOC_REQBUFS`ioctl 在捕获和输出设备上分配缓冲区，然后应用程序将输出设备的缓冲区导出为 DMABUF 文件描述符，并在捕获设备上的入队 ioctl 之前使用这些文件描述符来设置`v4l2_buffer.m.fd`字段。然后，排队的缓冲区将填充其对应的缓冲区（与`v4l2_buffer.m.fd`对应的输出设备缓冲区）。

在下面的示例中，我们将输出设备缓冲区导出为 DMABUF 文件描述符。这假设已经使用`VIDIOC_REQBUFS`ioctl 分配了此输出设备的缓冲区，其中`req.type`设置为`V4L2_BUF_TYPE_VIDEO_OUTPUT`，`req.memory`设置为`V4L2_MEMORY_DMABUF`：

```
int outdev_dmabuf_fd[BUF_COUNT] = {-1};
int i;
for (i = 0; i < req.count; i++) {
    struct v4l2_exportbuffer expbuf;
    CLEAR (expbuf);
    expbuf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
    expbuf.index = i;
    if (-1 == xioctl(fd, VIDIOC_EXPBUF, &expbuf)
        errno_exit ("VIDIOC_EXPBUF");
    outdev_dmabuf_fd[i] = expbuf.fd;
}
```

现在，我们已经了解了基于 DMABUF 的流式传输，并介绍了它所带来的概念。接下来和最后的流式传输方法要简单得多，需要的代码也更少。让我们来看看。

请求读/写 I/O 内存

从编码的角度来看，这是更简单的流式传输模式。在**读/写 I/O**的情况下，除了分配应用程序将存储读取数据的内存位置之外，没有其他事情要做，就像下面的示例中一样：

```
struct buffer_addr {
    void *start;
    size_t length;
};
struct buffer_addr *buf_addr;
buf_addr = calloc(1, sizeof(*buf_addr));
if (!buf_addr) {
    fprintf(stderr, "Out of memory\n");
    exit(EXIT_FAILURE);
}
buf_addr[0].length = buffer_size;
buf_addr[0].start = malloc(buffer_size);
if (!buf_addr[0].start) {
    fprintf(stderr, "Out of memory\n");
    exit(EXIT_FAILURE);
}
```

在前面的代码片段中，我们定义了相同的自定义数据结构`struct buffer_addr`。但是，这里没有真正的缓冲区请求（没有使用`VIDIOC_REQBUFS`），因为还没有任何东西传递给内核。缓冲区内存只是被分配了，就是这样。

现在，我们已经完成了缓冲区请求。下一步是将请求的缓冲区加入队列，以便内核可以用视频数据填充它们。现在让我们看看如何做到这一点。

## 将缓冲区加入队列并启用流式传输

在访问缓冲区并读取其数据之前，必须将该缓冲区加入队列。这包括在使用流式 I/O 方法（除了读/写 I/O 之外的所有方法）时，在缓冲区上使用`VIDIOC_QBUF` ioctl。将缓冲区加入队列将锁定该缓冲区在物理内存中的内存页面。这样，这些页面就无法被交换到磁盘上。请注意，这些缓冲区保持锁定状态，直到它们被出队列，直到调用`VIDIOC_STREAMOFF`或`VIDIOC_REQBUFS` ioctls，或者直到设备被关闭。

在 V4L2 上下文中，锁定缓冲区意味着将该缓冲区传递给驱动程序进行硬件访问（通常是 DMA）。如果应用程序访问（读/写）已锁定的缓冲区，则结果是未定义的。

要将缓冲区入队，应用程序必须准备`struct v4l2_buffer`，并根据缓冲区类型、流模式和分配缓冲区时的索引设置`v4l2_buffer.type`、`v4l2_buffer.memory`和`v4l2_buffer.index`。其他字段取决于流模式。

重要提示

*读/写 I/O*方法不需要入队。

### 主缓冲区的概念

对于捕获应用程序，通常在开始捕获并进入读取循环之前，入队一定数量（大多数情况下是分配的缓冲区数量）的空缓冲区是惯例。这有助于提高应用程序的流畅性，并防止因为缺少填充的缓冲区而被阻塞。这应该在分配缓冲区后立即完成。

### 入队用户指针缓冲区

要将用户指针缓冲区入队，应用程序必须将`v4l2_buffer.memory`成员设置为`V4L2_MEMORY_USERPTR`。这里的特殊之处在于`v4l2_buffer.m.userptr`字段，必须设置为先前分配的缓冲区的地址，并且`v4l2_buffer.length`设置为其大小。当使用多平面 API 时，必须使用传递的`struct v4l2_plane`数组的`m.userptr`和`length`成员：

```
/* Prime buffers */
for (i = 0; i < BUF_COUNT; ++i) {
    struct v4l2_buffer buf;
    CLEAR(buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_USERPTR; buf.index = i;
    buf.m.userptr = (unsigned long)buf_addr[i].start;
    buf.length = buf_addr[i].length;
    if (-1 == xioctl(fd, VIDIOC_QBUF, &buf))
        errno_exit("VIDIOC_QBUF");
}
```

### 入队内存映射缓冲区

要将内存映射缓冲区入队，应用程序必须通过设置`type`、`memory`（必须为`V4L2_MEMORY_MMAP`）和`index`成员来填充`struct v4l2_buffer`，就像以下摘录中所示：

```
/* Prime buffers */
for (i = 0; i < BUF_COUNT; ++i) {
    struct v4l2_buffer buf; CLEAR (buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = i;
    if (-1 == xioctl (fd, VIDIOC_QBUF, &buf))
        errno_exit ("VIDIOC_QBUF");
}
```

### 入队 DMABUF 缓冲区

要将输出设备的 DMABUF 缓冲区填充到捕获设备的缓冲区中，应用程序应填充`struct v4l2_buffer`，将`memory`字段设置为`V4L2_MEMORY_DMABUF`，将`type`字段设置为`V4L2_BUF_TYPE_VIDEO_CAPTURE`，将`m.fd`字段设置为与输出设备的 DMABUF 缓冲区关联的文件描述符，如下所示：

```
/* Prime buffers */
for (i = 0; i < BUF_COUNT; ++i) {
    struct v4l2_buffer buf; CLEAR (buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_DMABUF; buf.index	= i;
    buf.m.fd = outdev_dmabuf_fd[i];
    /* enqueue the dmabuf to capture device */
    if (-1 == xioctl (fd, VIDIOC_QBUF, &buf))
        errno_exit ("VIDIOC_QBUF");
}
```

上述代码摘录显示了 V4L2 DMABUF 导入的工作原理。ioctl 中的`fd`参数是与捕获设备关联的文件描述符，在`open()`系统调用中获得。`outdev_dmabuf_fd`是包含输出设备的 DMABUF 文件描述符的数组。您可能会想知道，这如何能在不是 V4L2 但是兼容 DRM 的输出设备上工作，例如。以下是一个简要的解释。

首先，DRM 子系统以驱动程序相关的方式提供 API，您可以使用这些 API 在 GPU 上分配（愚笨的）缓冲区，它将返回一个 GEM 句柄。DRM 还提供了`DRM_IOCTL_PRIME_HANDLE_TO_FD` ioctl，允许通过`PRIME`将缓冲区导出到 DMABUF 文件描述符，然后使用`drmModeAddFB2()` API 创建一个`framebuffer`对象（这是将要读取和显示在屏幕上的东西，或者我应该说，确切地说是 CRT 控制器），对应于这个缓冲区，最终可以使用`drmModeSetPlane()`或`drmModeSetPlane()`API 进行渲染。然后，应用程序可以使用`DRM_IOCTL_PRIME_HANDLE_TO_FD` ioctl 返回的文件描述符设置`v4l2_requestbuffers.m.fd`字段。然后，在读取循环中，在每个`VIDIOC_DQBUF` ioctl 之后，应用程序可以使用`drmModeSetPlane()`API 更改平面的帧缓冲区和位置。

重要提示

`drm dma-buf`接口层集成了`GEM`，这是 DRM 子系统支持的内存管理器之一

### 启用流式传输

启用流式传输有点像通知 V4L2 从现在开始将*输出*队列作为访问对象。应用程序应使用`VIDIOC_STREAMON`来实现这一点。以下是一个示例：

```
/* Start streaming */
int ret;
int a = V4L2_BUF_TYPE_VIDEO_CAPTURE;
ret = xioctl(capt.fd, VIDIOC_STREAMON, &a);
if (ret < 0) {
    perror("VIDIOC_STREAMON\n");
    return -1;
}
```

上述摘录很短，但是必须启用流式传输，否则稍后无法出队缓冲区。

## 出队缓冲区

这实际上是应用程序的读取循环的一部分。应用程序使用`VIDIOC_DQBUF` ioctl 出队缓冲区。只有在流启用之后才可能。当应用程序调用`VIDIOC_DQBUF` ioctl 时，它指示驱动程序检查是否有任何已填充的缓冲区（在`open()`系统调用期间设置了`O_NONBLOCK`标志），直到缓冲区排队并填充。

重要提示

尝试在排队之前出队缓冲区是一个错误，`VIDIOC_DQBUF` ioctl 应该返回`-EINVAL`。当`O_NONBLOCK`标志给定给`open()`函数时，当没有可用的缓冲区时，`VIDIOC_DQBUF`立即返回`EAGAIN`错误代码。

出队缓冲区并处理其数据后，应用程序必须立即将此缓冲区重新排队，以便为下一次读取重新填充，依此类推。

### 出队内存映射缓冲区

以下是一个出队已经内存映射的缓冲区的示例：

```
struct v4l2_buffer buf;
CLEAR (buf);
buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
buf.memory = V4L2_MEMORY_MMAP;
if (-1 == xioctl (fd, VIDIOC_DQBUF, &buf)) {
    switch (errno) {
    case EAGAIN:
        return 0;
    case EIO:
    default:
        errno_exit ("VIDIOC_DQBUF");
    }
}
/* make sure the returned index is coherent with the number
 * of buffers allocated  */
assert (buf.index < BUF_COUNT);
/* We use buf.index to point to the correct entry in our  * buf_addr  */ 
process_image(buf_addr[buf.index].start);
/* Queue back this buffer again, after processing is done */
if (-1 == xioctl (fd, VIDIOC_QBUF, &buf))
    errno_exit ("VIDIOC_QBUF");
```

这可以在循环中完成。例如，假设您需要 200 张图像。读取循环可能如下所示：

```
#define MAXLOOPCOUNT 200
/* Start the loop of capture */
for (i = 0; i < MAXLOOPCOUNT; i++) {
    struct v4l2_buffer buf;
    CLEAR (buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    if (-1 == xioctl (fd, VIDIOC_DQBUF, &buf)) {
        [...]
    }
   /* Queue back this buffer again, after processing is done */
    [...]
}
```

上面的片段只是使用循环重新实现了缓冲区出队，其中计数器表示需要抓取的图像数量。

### 出队用户指针缓冲区

以下是使用**用户指针**出队缓冲区的示例：

```
struct v4l2_buffer buf; int i;
CLEAR (buf);
buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
buf.memory = V4L2_MEMORY_USERPTR;
/* Dequeue a captured buffer */
if (-1 == xioctl (fd, VIDIOC_DQBUF, &buf)) {
    switch (errno) {
    case EAGAIN:
        return 0;
    case EIO:
        [...]
    default:
        errno_exit ("VIDIOC_DQBUF");
    }
}
/*
 * We may need the index to which corresponds this buffer
 * in our buf_addr array. This is done by matching address
 * returned by the dequeue ioctl with the one stored in our
 * array  */
for (i = 0; i < BUF_COUNT; ++i)
    if (buf.m.userptr == (unsigned long)buf_addr[i].start &&
                        buf.length == buf_addr[i].length)
        break;
/* the corresponding index is used for sanity checks only */ 
assert (i < BUF_COUNT);
process_image ((void *)buf.m.userptr);
/* requeue the buffer */
if (-1 == xioctl (fd, VIDIOC_QBUF, &buf))
    errno_exit ("VIDIOC_QBUF");
```

上面的代码展示了如何出队用户指针缓冲区，并且有足够的注释，不需要进一步解释。然而，如果需要许多缓冲区，这可以在循环中实现。

### 读/写 I/O

这是最后一个示例，展示了如何使用`read()`系统调用出队缓冲区：

```
if (-1 == read (fd, buffers[0].start, buffers[0].length)) {
    switch (errno) {
    case EAGAIN:
        return 0;
    case EIO:
        [...]
    default:
        errno_exit ("read");
    }
}
process_image (buffers[0].start);
```

之前的示例没有详细讨论，因为它们每个都使用了在*V4L2 用户空间 API*部分已经介绍的概念。现在我们已经熟悉了编写 V4L2 用户空间代码，让我们看看如何通过使用专用工具来快速原型设计摄像头系统而不编写任何代码。

# V4L2 用户空间工具

到目前为止，我们已经学会了如何编写用户空间代码与内核中的驱动程序进行交互。对于快速原型设计和测试，我们可以利用一些社区提供的 V4L2 用户空间工具。通过使用这些工具，我们可以专注于系统设计并验证摄像头系统。最知名的工具是`v4l2-ctl`，我们将重点关注它；它随`v4l-utils`软件包一起提供。

尽管本章没有讨论，但还有**yavta**工具（代表**Yet Another V4L2 Test Application**），它可以用于测试、调试和控制摄像头子系统。

## 使用 v4l2-ctl

`v4l2-utils`是一个用户空间应用程序，可用于查询或配置 V4L2 设备（包括子设备）。该工具可以帮助设置和设计精细的基于 V4L2 的系统，因为它有助于调整和利用设备的功能。

重要提示

`qv4l2`是`v4l2-ctl`的 Qt GUI 等效物。`v4l2-ctl`非常适合嵌入式系统，而`qv4l2`非常适合交互式测试。

### 列出视频设备及其功能

首先，我们需要使用`--list-devices`选项列出所有可用的视频设备：

```
# v4l2-ctl --list-devices
Integrated Camera: Integrated C (usb-0000:00:14.0-8):
	/dev/video0
	/dev/video1
```

如果有多个设备可用，我们可以在任何`v4l2-ctl`命令之后使用`-d`选项来针对特定设备。请注意，如果未指定`-d`选项，默认情况下会针对`/dev/video0`。

要获取有关特定设备的信息，必须使用`-D`选项，如下所示：

```
# v4l2-ctl -d /dev/video0 -D
Driver Info (not using libv4l2):
	Driver name   : uvcvideo
	Card type     : Integrated Camera: Integrated C
	Bus info      : usb-0000:00:14.0-8
	Driver version: 5.4.60
	Capabilities  : 0x84A00001
		Video Capture
		Metadata Capture
		Streaming
		Extended Pix Format
		Device Capabilities
	Device Caps   : 0x04200001
		Video Capture
		Streaming
		Extended Pix Format
```

上面的命令显示了设备信息（如驱动程序及其版本）以及其功能。也就是说，`--all`命令提供更好的详细信息。你应该试一试。

### 更改设备属性（控制设备）

在查看更改设备属性之前，我们首先需要知道设备支持的控制、它们的值类型（整数、布尔、字符串等）、它们的默认值以及接受的值是什么。

为了获取设备支持的控制列表，我们可以使用`v4l2-ctl`和`-L`选项，如下所示：

```
# v4l2-ctl -L
                brightness 0x00980900 (int)  : min=0 max=255 step=1 default=128 value=128
                contrast 0x00980901 (int)    : min=0 max=255 step=1 default=32 value=32
                saturation 0x00980902 (int)  : min=0 max=100 step=1 default=64 value=64
                     hue 0x00980903 (int)    : min=-180 max=180 step=1 default=0 value=0
 white_balance_temperature_auto 0x0098090c (bool)   : default=1 value=1
                     gamma 0x00980910 (int)  : min=90 max=150 step=1 default=120 value=120
         power_line_frequency 0x00980918 (menu)   : min=0 max=2 default=1 value=1
				0: Disabled
				1: 50 Hz
				2: 60 Hz
      white_balance_temperature 0x0098091a (int)  : min=2800 max=6500 step=1 default=4600 value=4600 flags=inactive
                    sharpness 0x0098091b (int)    : min=0 max=7 step=1 default=3 value=3
       backlight_compensation 0x0098091c (int)    : min=0 max=2 step=1 default=1 value=1
                exposure_auto 0x009a0901 (menu)   : min=0 max=3 default=3 value=3
				1: Manual Mode
				3: Aperture Priority Mode
         exposure_absolute 0x009a0902 (int)    : min=5 max=1250 step=1 default=157 value=157 flags=inactive
         exposure_auto_priority 0x009a0903 (bool)   : default=0 value=1
jma@labcsmart:~$
```

在上述输出中，`"value="`字段返回控制的当前值，其他字段都是不言自明的。

既然我们已经知道设备支持的控制列表，控制值可以通过`--set-ctrl`选项进行更改，如下例所示：

```
# v4l2-ctl --set-ctrl brightness=192
```

之后，我们可以使用以下命令检查当前值：

```
# v4l2-ctl -L
                 brightness 0x00980900 (int)    : min=0 max=255 step=1 default=128 value=192
                     [...]
```

或者，我们可以使用`--get-ctrl`命令，如下所示：

```
# v4l2-ctl --get-ctrl brightness 
brightness: 192
```

现在可能是时候调整设备了。在此之前，让我们先检查一下设备的视频特性。

设置像素格式、分辨率和帧率

在选择特定格式或分辨率之前，我们需要列举设备可用的内容。为了获取支持的像素格式、分辨率和帧率，需要向`v4l2-ctl`提供`--list-formats-ext`选项，如下所示：

```
# v4l2-ctl --list-formats-ext
ioctl: VIDIOC_ENUM_FMT
	Index       : 0
	Type        : Video Capture
	Pixel Format: 'MJPG' (compressed)
	Name        : Motion-JPEG
		Size: Discrete 1280x720
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 960x540
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 848x480
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 640x480
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 640x360
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 424x240
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 352x288
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 320x240
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 320x180
			Interval: Discrete 0.033s (30.000 fps)
	Index       : 1
	Type        : Video Capture
	Pixel Format: 'YUYV'
	Name        : YUYV 4:2:2
		Size: Discrete 1280x720
			Interval: Discrete 0.100s (10.000 fps)
		Size: Discrete 960x540
			Interval: Discrete 0.067s (15.000 fps)
		Size: Discrete 848x480
			Interval: Discrete 0.050s (20.000 fps)
		Size: Discrete 640x480
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 640x360
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 424x240
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 352x288
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 320x240
			Interval: Discrete 0.033s (30.000 fps)
		Size: Discrete 320x180
			Interval: Discrete 0.033s (30.000 fps)
```

从上述输出中，我们可以看到目标设备支持的内容，即`mjpeg`压缩格式和 YUYV 原始格式。

现在，为了更改摄像头配置，首先使用`--set-parm`选项选择帧率，如下所示：

```
# v4l2-ctl --set-parm=30
Frame rate set to 30.000 fps
#
```

然后，可以使用`--set-fmt-video`选项选择所需的分辨率和/或像素格式，如下所示：

```
# v4l2-ctl --set-fmt-video=width=640,height=480,  pixelformat=MJPG
```

在帧率方面，您可能希望使用`v4l2-ctl`和`--set-parm`选项，只提供帧率的分子—分母固定为`1`（只允许整数帧率值）—如下所示：

```
# v4l2-ctl --set-parm=<framerate numerator>
```

### 捕获帧和流处理

`v4l2-ctl`支持的选项比您想象的要多得多。为了查看可能的选项，可以打印适当部分的帮助消息。与流处理和视频捕获相关的常见帮助命令如下：

+   `--help-streaming`：打印所有与流处理相关的选项的帮助消息

+   `--help-subdev`：打印所有与`v4l-subdevX`设备相关的选项的帮助消息

+   `--help-vidcap`：打印所有获取/设置/列出视频捕获格式的选项的帮助消息

从这些帮助命令中，我已经构建了以下命令，以便在磁盘上捕获 QVGA MJPG 压缩帧：

```
# v4l2-ctl --set-fmt-video=width=320,height=240,  pixelformat=MJPG \
   --stream-mmap --stream-count=1 --stream-to=grab-320x240.mjpg
```

我还使用以下命令捕获了一个具有相同分辨率的原始 YUV 图像：

```
# v4l2-ctl --set-fmt-video=width=320,height=240,  pixelformat=YUYV \
  --stream-mmap --stream-count=1 --stream-to=grab-320x240-yuyv.raw
```

除非使用一个体面的原始图像查看器，否则无法显示原始 YUV 图像。为了做到这一点，必须使用`ffmpeg`工具转换原始图像，例如如下所示：

```
# ffmpeg -f rawvideo -s 320x240 -pix_fmt yuyv422 \
         -i grab-320x240-yuyv.raw grab-320x240.png
```

您可以注意到原始图像和压缩图像之间的大小差异很大，如下摘录所示：

```
# ls -hl grab-320x240.mjpg
-rw-r--r-- 1 root root 8,0K oct.  21 20:26 grab-320x240.mjpg
# ls -hl grab-320x240-yuyv.raw 
-rw-r--r-- 1 root root 150K oct.  21 20:26 grab-320x240-yuyv.raw
```

请注意，在原始捕获的文件名中包含图像格式是一个好习惯（例如在`grab-320x240-yuyv.raw`中包含`yuyv`），这样您就可以轻松地从正确的格式进行转换。对于压缩图像格式，这条规则是不必要的，因为这些格式是带有描述其后的像素数据的标头的图像容器格式，并且可以很容易地使用`gst-typefind-1.0`工具进行读取。JPEG 就是这样一种格式，以下是如何读取其标头的方法：

```
# gst-typefind-1.0 grab-320x240.mjpg 
grab-320x240.mjpg - image/jpeg, width=(int)320, height=(int)240, sof-marker=(int)0
# gst-typefind-1.0 grab-320x240-yuyv.raw 
grab-320x240-yuyv.raw - FAILED: Could not determine type of stream.
```

现在我们已经完成了工具的使用，让我们看看如何深入了解 V4L2 调试以及从用户空间开始学习。

## 在用户空间调试 V4L2

由于我们的视频系统设置可能不是没有错误的，V4L2 为了从用户空间进行跟踪和排除来自 VL4L2 框架核心或用户空间 API 的故障，提供了一个简单但大的后门调试。

可以按照以下步骤启用框架调试：

```
# echo 0x3 > /sys/module/videobuf2_v4l2/parameters/debug
# echo 0x3 > /sys/module/videobuf2_common/parameters/debug
```

上述命令将指示 V4L2 向内核日志消息添加核心跟踪。这样，它将很容易地跟踪故障的来源，假设故障来自核心。运行以下命令：

```
# dmesg
[831707.512821] videobuf2_common: __setup_offsets: buffer 0, plane 0 offset 0x00000000
[831707.512915] videobuf2_common: __setup_offsets: buffer 1, plane 0 offset 0x00097000
[831707.513003] videobuf2_common: __setup_offsets: buffer 2, plane 0 offset 0x0012e000
[831707.513118] videobuf2_common: __setup_offsets: buffer 3, plane 0 offset 0x001c5000
[831707.513119] videobuf2_common: __vb2_queue_alloc: allocated 4 buffers, 1 plane(s) each
[831707.513169] videobuf2_common: vb2_mmap: buffer 0, plane 0 successfully mapped
[831707.513176] videobuf2_common: vb2_core_qbuf: qbuf of buffer 0 succeeded
[831707.513205] videobuf2_common: vb2_mmap: buffer 1, plane 0 successfully mapped
[831707.513208] videobuf2_common: vb2_core_qbuf: qbuf of buffer 1 succeeded
[...]
```

在先前的内核日志消息中，我们可以看到与内核相关的 V4L2 核心函数调用，以及一些其他细节。如果由于任何原因 V4L2 核心跟踪不是必要的或者对您来说不够，您还可以使用以下命令启用 V4L2 用户空间 API 跟踪：

```
$ echo 0x3 > /sys/class/video4linux/video0/dev_debug
```

运行命令后，允许您捕获原始图像，我们可以在内核日志消息中看到以下内容：

```
$ dmesg
[833211.742260] video0: VIDIOC_QUERYCAP: driver=uvcvideo, card=Integrated Camera: Integrated C, bus=usb-0000:00:14.0-8, version=0x0005043c, capabilities=0x84a00001, device_caps=0x04200001
[833211.742275] video0: VIDIOC_QUERY_EXT_CTRL: id=0x980900, type=1, name=Brightness, min/max=0/255, step=1, default=128, flags=0x00000000, elem_size=4, elems=1, nr_of_dims=0, dims=0,0,0,0
[...]
[833211.742318] video0: VIDIOC_QUERY_EXT_CTRL: id=0x98090c, type=2, name=White Balance Temperature, Auto, min/max=0/1, step=1, default=1, flags=0x00000000, elem_size=4, elems=1, nr_of_dims=0, dims=0,0,0,0
[833211.742365] video0: VIDIOC_QUERY_EXT_CTRL: id=0x98091c, type=1, name=Backlight Compensation, min/max=0/2, step=1, default=1, flags=0x00000000, elem_size=4, elems=1, nr_of_dims=0, dims=0,0,0,0
[833211.742376] video0: VIDIOC_QUERY_EXT_CTRL: id=0x9a0901, type=3, name=Exposure, Auto, min/max=0/3, step=1, default=3, flags=0x00000000, elem_size=4, elems=1, nr_of_dims=0, dims=0,0,0,0
[...]
[833211.756641] videobuf2_common: vb2_mmap: buffer 1, plane 0 successfully mapped
[833211.756646] videobuf2_common: vb2_core_qbuf: qbuf of buffer 1 succeeded
[833211.756649] video0: VIDIOC_QUERYBUF: 00:00:00.00000000 index=2, type=vid-cap, request_fd=0, flags=0x00012000, field=any, sequence=0, memory=mmap, bytesused=0, offset/userptr=0x12e000, length=614989
[833211.756657] timecode=00:00:00 type=0, flags=0x00000000, frames=0, userbits=0x00000000
[833211.756698] videobuf2_common: vb2_mmap: buffer 2, plane 0 successfully mapped
[833211.756704] videobuf2_common: vb2_core_qbuf: qbuf of buffer 2 succeeded
[833211.756706] video0: VIDIOC_QUERYBUF: 00:00:00.00000000 index=3, type=vid-cap, request_fd=0, flags=0x00012000, field=any, sequence=0, memory=mmap, bytesused=0, offset/userptr=0x1c5000, length=614989
[833211.756714] timecode=00:00:00 type=0, flags=0x00000000, frames=0, userbits=0x00000000
[833211.756751] videobuf2_common: vb2_mmap: buffer 3, plane 0 successfully mapped
[833211.756755] videobuf2_common: vb2_core_qbuf: qbuf of buffer 3 succeeded
[833212.967229] videobuf2_common: vb2_core_streamon: successful
[833212.967234] video0: VIDIOC_STREAMON: type=vid-cap
```

在先前的输出中，我们可以跟踪不同的 V4L2 用户空间 API 调用，这些调用对应于不同的`ioctl`命令及其参数。

### V4L2 合规性驱动程序测试

为了使驱动程序符合 V4L2 标准，它必须满足一些标准，其中包括通过`v4l2-compliance`工具测试，该工具用于测试各种类型的 V4L 设备。`v4l2-compliance`试图测试 V4L2 设备的几乎所有方面，并涵盖几乎所有 V4L2 ioctls。

与其他 V4L2 工具一样，可以使用`-d`或`--device=`命令来定位视频设备。如果未指定设备，则将定位到`/dev/video0`。以下是一个输出摘录：

```
# v4l2-compliance
v4l2-compliance SHA   : not available
Driver Info:
	Driver name   : uvcvideo
	Card type     : Integrated Camera: Integrated C
	Bus info      : usb-0000:00:14.0-8
	Driver version: 5.4.60
	Capabilities  : 0x84A00001
		Video Capture
		Metadata Capture
		Streaming
		Extended Pix Format
		Device Capabilities
	Device Caps   : 0x04200001
		Video Capture
		Streaming
		Extended Pix Format
Compliance test for device /dev/video0 (not using libv4l2):
Required ioctls:
	test VIDIOC_QUERYCAP: OK
Allow for multiple opens:
	test second video open: OK
	test VIDIOC_QUERYCAP: OK
	test VIDIOC_G/S_PRIORITY: OK
	test for unlimited opens: OK
Debug ioctls:
	test VIDIOC_DBG_G/S_REGISTER: OK (Not Supported)
	test VIDIOC_LOG_STATUS: OK (Not Supported)
[]
Output ioctls:
	test VIDIOC_G/S_MODULATOR: OK (Not Supported)
	test VIDIOC_G/S_FREQUENCY: OK (Not Supported)
[...]
Test input 0:
	Control ioctls:
		fail: v4l2-test-controls.cpp(214): missing control class for class 00980000
		fail: v4l2-test-controls.cpp(251): missing control class for class 009a0000
		test VIDIOC_QUERY_EXT_CTRL/QUERYMENU: FAIL
		test VIDIOC_QUERYCTRL: OK
		fail: v4l2-test-controls.cpp(437): s_ctrl returned an error (84)
		test VIDIOC_G/S_CTRL: FAIL
		fail: v4l2-test-controls.cpp(675): s_ext_ctrls returned an error (
```

在先前的日志中，我们可以看到已定位到`/dev/video0`。此外，我们注意到我们的驱动程序不支持`Debug ioctls`和`Output ioctls`（这些不是失败）。尽管输出已经足够详细，但最好也使用`--verbose`命令，这样输出会更加用户友好和更加详细。因此，毫无疑问，如果要提交新的 V4L2 驱动程序，该驱动程序必须通过 V4L2 合规性测试。

# 摘要

在本章中，我们介绍了 V4L2 的用户空间实现。我们从视频流的 V4L2 缓冲区管理开始。我们还学习了如何处理视频设备属性管理，都是从用户空间进行的。然而，V4L2 是一个庞大的框架，不仅在代码方面，而且在功耗方面也是如此。因此，在下一章中，我们将讨论 Linux 内核的电源管理，以使系统在不降低系统性能的情况下保持尽可能低的功耗水平。


# 第十章：Linux 内核功耗管理

移动设备变得越来越复杂，具有越来越多的功能，以追随商业趋势并满足消费者的需求。虽然这些设备的一些部分运行专有或裸机软件，但它们大多数运行基于 Linux 的操作系统（嵌入式 Linux 发行版，Android 等），并且全部都是由电池供电。除了完整的功能和性能外，消费者需要尽可能长的自主时间和持久的电池。毫无疑问，完整的性能和自主时间（节能）是两个完全不兼容的概念，必须在使用设备时始终找到一个折衷方案。这种折衷方案就是功耗管理，它允许我们在不忽视设备进入低功耗状态后唤醒（或完全运行）所需的时间的情况下处理尽可能低的功耗和设备性能。

Linux 内核配备了几种功耗管理功能，从允许您在短暂的空闲期间节省电力（或执行功耗较低的任务）到在系统不活跃使用时将整个系统置于睡眠状态。

此外，随着设备被添加到系统中，它们可以通过 Linux 内核提供的通用功耗管理 API 参与功耗管理工作，以便允许设备驱动程序开发人员从设备中实现的功耗管理机制中受益。这允许调整每个设备或整个系统的功耗参数，以延长设备的自主时间和电池的寿命。

在本章中，我们将深入了解 Linux 内核功耗管理子系统，利用其 API 并从用户空间管理其选项。因此，将涵盖以下主题：

+   基于 Linux 的系统上的功耗管理概念

+   向设备驱动程序添加功耗管理功能

+   作为系统唤醒的源头

# 技术要求

为了更好地理解本章，您需要以下内容：

+   基本的电气知识

+   基本的 C 编程技能

+   良好的计算机架构知识

+   Linux 内核 4.19 源代码可在[`github.com/torvalds/linux`](https://github.com/torvalds/linux)上找到

# 基于 Linux 的系统上的功耗管理概念

**功耗管理**（**PM**）意味着在任何时候尽可能消耗尽可能少的电力。操作系统必须处理两种类型的功耗管理：**设备功耗管理**和**系统功耗管理**。

+   **设备功耗管理**：这是特定于设备的。它允许在系统运行时将设备置于低功耗状态。这可能允许，除其他事项外，当前未使用的设备部分关闭以节省电力，例如在不键入时关闭键盘背光。无论功耗管理活动如何，都可以显式地在设备上调用单个设备功耗管理，或者在设备空闲一定时间后自动发生。设备功耗管理是所谓的*运行时功耗管理*的别名。

+   **系统电源管理**，也称为*睡眠状态*：这使平台可以进入系统范围的低功耗状态。换句话说，进入睡眠状态是将整个系统置于低功耗状态的过程。根据平台、其功能和目标唤醒延迟，系统可能进入几种低功耗状态（或睡眠状态）。例如，当笔记本电脑的盖子关闭时，当手机屏幕关闭时，或者达到某些关键状态（例如电池电量）时，就会发生这种情况。许多这些状态在各个平台上都是相似的（例如冻结，这纯粹是软件，因此不依赖于设备或系统），并且将在以后详细讨论。总体概念是在系统关闭电源之前保存运行系统的状态（或将其置于睡眠状态，这与关闭不同），并在系统重新获得电源后恢复。这可以防止系统执行整个关闭和启动序列。

尽管系统 PM 和运行时 PM 处理空闲管理的不同情景，但部署两者都很重要，以防止平台浪费电力。正如我们将在接下来的章节中看到的那样，您应该将它们视为互补的。

## 运行时功耗管理

这是 Linux PM 的一部分，它在不将整个系统置于低功耗状态的情况下管理单个设备的电源。在这种模式下，操作在系统运行时生效，因此被称为运行时电源管理。为了适应设备的功耗，其属性在系统仍在运行时进行了更改，因此也被称为**动态功耗管理**。

### 一些动态功耗管理接口的介绍

除了驱动程序开发人员可以在设备驱动程序中实现的每个设备的功耗管理能力之外，Linux 内核还提供了用户空间接口来添加/删除/修改电源策略。其中最著名的列在这里：

+   **CPU 空闲**：这有助于在 CPU 没有任务可执行时管理 CPU 功耗。

+   **CPUFreq**：这允许根据系统负载更改 CPU 功率属性（即电压和频率）。

+   **热量**：这允许根据系统预定义区域中感测到的温度调整功率属性，大多数情况下是靠近 CPU 的区域。

您可能已经注意到前面的策略涉及 CPU。这是因为 CPU 是移动设备（或嵌入式系统）上功耗的主要来源之一。虽然下一节只介绍了三个接口，但也存在其他接口，例如 QoS 和 DevFreq。读者可以自由探索这些接口以满足他们的好奇心。

#### CPU 空闲

每当系统中的逻辑 CPU 没有任务可执行时，可能需要将其置于特定状态以节省电力。在这种情况下，大多数操作系统简单地安排所谓的*空闲线程*。在执行此线程时，CPU 被称为空闲状态。`C0`是正常的 CPU 工作模式；换句话说，CPU 处于 100%开启状态。随着 C 编号的增加，CPU 睡眠模式变得更深；换句话说，更多的电路和信号被关闭，CPU 需要返回`C0`模式的时间也更长，也就是唤醒的时间。`C1`是第一个 C 状态，`C2`是第二个状态，依此类推。当逻辑处理器处于空闲状态（任何 C 状态除`C0`之外），其频率通常为`0`。

下一个事件（按时间顺序）决定 CPU 可以休眠多长时间。每个空闲状态由三个特征描述：

+   退出延迟，单位为µS：这是退出此状态所需的延迟时间。

+   功耗，单位为 mW：这并不总是可靠的。

+   目标驻留时间，单位为µS：这是使此状态变得有趣的空闲持续时间。

CPU 空闲驱动程序是特定于平台的，Linux 内核期望 CPU 驱动程序支持最多 10 个状态（请参阅内核源代码中的`CPUIDLE_STATE_MAX`）。但是，实际状态的数量取决于底层 CPU 硬件（其中嵌入了内置的节能逻辑），大多数 ARM 平台只提供一个或两个空闲状态。进入的状态选择基于由州长管理的策略。

在这种情况下，州长是实现算法的简单模块，使得可以根据某些属性做出最佳的 C 状态选择。换句话说，州长决定系统的目标 C 状态。虽然系统上可能存在多个州长，但在任何时候只有一个州长控制给定的 CPU。它设计成这样，如果调度程序运行队列为空（这意味着 CPU 没有其他事情要做）并且需要使 CPU 空闲，它将请求 CPU 空闲到 CPU 空闲框架。然后，框架将依赖于当前选择的州长来选择适当的*C 状态*。有两个 CPU 空闲州长：`ladder`（用于周期性定时器基础系统）和`menu`（用于无滴答系统）。虽然`ladder`州长始终可用，但如果选择了`CONFIG_CPU_IDLE`，则`menu`州长另外需要设置`CONFIG_NO_HZ_IDLE`（或在较旧的内核上设置`CONFIG_NO_HZ`）。在配置内核时选择州长。粗略地说，使用哪个取决于内核的配置，特别是取决于调度程序滴答是否可以被空闲循环停止，因此取决于`CONFIG_NO_HZ_IDLE`。您可以参考`Documentation/timers/NO_HZ.txt`以获取更多关于此的信息。

州长可以决定是继续保持当前状态还是转换到另一个状态，如果是后者，它将指示当前驱动程序转换到所选状态。可以通过读取`/sys/devices/system/cpu/cpuidle/current_driver`文件来识别当前空闲驱动程序，通过`/sys/devices/system/cpu/cpuidle/current_governor_ro`来获取当前的州长：

```
$ cat /sys/devices/system/cpu/cpuidle/current_governor_ro menu
```

在给定系统上，`/sys/devices/system/cpu/cpuX/cpuidle/`中的每个目录对应一个 C 状态，并且每个 C 状态目录属性文件的内容描述了这个 C 状态：

```
$ ls /sys/devices/system/cpu/cpu0/cpuidle/
state0 state1 state2 state3 state4 state5 state6 state7 state8
$ ls /sys/devices/system/cpu/cpu0/cpuidle/state0/
above below desc disable latency name power residency time usage
```

在 ARM 平台上，空闲状态可以在设备树中描述。您可以查阅内核源中的`Documentation/devicetree/bindings/arm/idle-states.txt`文件以获取更多关于此的信息。

重要提示

与其他电源管理框架不同，CPU 空闲不需要用户干预即可工作。

有一个与此略有相似的框架，即`CPU 热插拔`，它允许在运行时动态启用和禁用 CPU，而无需重新启动系统。例如，要从系统中热插拔 CPU＃2，可以使用以下命令：

```
# echo 0 > /sys/devices/system/cpu/cpu2/online
```

我们可以通过读取`/proc/cpuinfo`来确保 CPU＃2 实际上已禁用：

```
# grep processor /proc/cpuinfo
processor	: 0
processor	: 1
processor	: 3
processor	: 4
processor	: 5
processor	: 6
processor	: 7
```

前面的内容证实了 CPU2 现在已经离线。为了将该 CPU 重新插入系统，我们可以执行以下命令：

```
# echo 1 > /sys/devices/system/cpu/cpu2/online
```

CPU 热插拔在底层会根据特定的硬件和驱动程序而有所不同。在某些系统上，它可能只是将 CPU 置于空闲状态，而在其他系统上，可能会从指定的核心中断电。

#### CPU 频率或动态电压和频率缩放（DVFS）

该框架允许根据约束和要求、用户偏好或其他因素对 CPU 进行动态电压选择和频率缩放。因为该框架涉及频率，所以它无条件地涉及时钟框架。该框架使用`{频率，电压}`元组的概念。

OPP 可以在设备树中描述，并且内核源中的绑定文档可以作为更多信息的良好起点：`Documentation/devicetree/bindings/opp/opp.txt`。

重要提示

您偶尔会在基于英特尔的机器上遇到术语`ls /sys/devices/system/cpu/cpufreq/`。因此，C 状态是空闲节能状态，与 P 状态相反，后者是执行节能状态。

CPUfreq 还使用了州长的概念（实现了缩放算法），该框架中的州长如下：

+   `ondemand`：这个州长对 CPU 的负载进行采样，并积极地将其扩展，以提供适当的处理能力，但在必要时将频率重置为最大值。

+   `conservative`：这类似于`ondemand`，但使用了一种不那么激进的增加 OPP 的方法。例如，即使系统突然需要高性能，它也不会从最低的 OPP 跳到最高的 OPP。它会逐渐增加。

+   `performance`：这个州长总是选择具有最高频率的 OPP。这个州长优先考虑性能。

+   `powersave`：与性能相反，这个州长总是选择具有最低频率的 OPP。这个州长优先考虑节能。

+   `userspace`：这个州长允许用户使用在`/sys/devices/system/cpu/cpuX/cpufreq/scaling_available_frequencies`中找到的任何值来设置所需的 OPP，通过将其回显到`/sys/devices/system/cpu/cpuX/cpufreq/scaling_setspeed`。

+   `schedutil`：这个州长是调度程序的一部分，因此它可以在内部访问调度程序数据结构，从而能够更可靠和准确地获取有关系统负载的统计信息，以更好地选择适当的 OPP。

`userspace`州长是唯一允许用户选择 OPP 的州长。对于其他州长，根据其算法的系统负载，OPP 的更改会自动发生。也就是说，从`userspace`开始，可用的州长如下所示：

```
$ cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors
performance powersave
```

要查看当前的州长，执行以下命令：

```
$ cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
powersave
```

要设置州长，可以使用以下命令：

```
$ echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

要查看当前的 OPP（频率以 kHz 为单位），执行以下命令：

```
$ cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 800031
```

要查看支持的 OPP（以 kHz 为单位的频率），执行以下命令：

```
$ cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies
275000 500000 600000 800031
```

要更改 OPP，可以使用以下命令：

```
$ echo 275000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed
```

重要提示

还有`devfreq`框架，它是一个通用的`Ondemand`、`performance`、`powersave`和`passive`。

请注意，前面的命令仅在选择了`ondemand`州长时才有效，因为它是唯一允许更改 OPP 的州长。但是，在所有前面的命令中，`cpu0`仅用于教学目的。将其视为*cpuX*，其中*X*是系统看到的 CPU 的索引。

#### 热

该框架致力于监控系统温度。它根据温度阈值具有专门的配置文件。热传感器感知热点并报告。该框架与冷却设备一起工作，后者有助于控制/限制过热的功耗散失。

热框架使用以下概念：

+   **热区**：您可以将热区视为需要监视温度的硬件。

+   **热传感器**：这些是用于进行温度测量的组件。热传感器在热区提供温度感应能力。

+   **冷却设备**：这些设备在功耗控制方面提供控制。通常有两种冷却方法：被动冷却，包括调节设备性能，此时使用 DVFS；和主动冷却，包括激活特殊的冷却设备，如风扇（GPIO 风扇，PWM 风扇）。

+   **触发点**：这些描述了建议进行冷却操作的关键温度（实际上是阈值）。这些点集是基于硬件限制选择的。

+   **州长们**：这些包括根据某些标准选择最佳冷却的算法。

+   **冷却映射**：这些用于描述触发点和冷却设备之间的链接。

热框架可以分为四个部分，分别是`热区`，`热管理器`，`热冷却`和`热核`，它是前三个部分之间的粘合剂。它可以在用户空间中从`/sys/class/thermal/`目录中进行管理：

```
$ ls /sys/class/thermal/
cooling_device0  cooling_device4 cooling_device8  thermal_zone3  thermal_zone7
cooling_device1  cooling_device5 thermal_zone0    thermal_zone4
cooling_device2  cooling_device6 thermal_zone1    thermal_zone5
cooling_device3  cooling_device7 thermal_zone2    thermal_zone6
```

在前面的内容中，每个`thermal_zoneX`文件代表一个热区驱动程序，或者热驱动程序。热区驱动程序是与热区相关的热传感器的驱动程序。该驱动程序公开了需要冷却的触发点，但也提供了与传感器相关的冷却设备列表。热工作流程旨在通过热区驱动程序获取温度，然后通过热管理器做出决策，最后通过热冷却进行温度控制。有关此内容的更多信息，请参阅内核源中的热 sysfs 文档，`Documentation/thermal/sysfs- api.txt`。此外，热区描述，触发点定义和冷却设备绑定可以在设备树中执行，其相关文档在源中的`Documentation/devicetree/bindings/thermal/thermal.txt`中。

## 系统电源管理睡眠状态

系统电源管理针对整个系统。其目的是将其置于低功耗状态。在这种低功耗状态下，系统消耗的功率很小，但维持相对较低的响应延迟。功率和响应延迟的确切数量取决于系统所处的睡眠状态有多深。这也被称为静态电源管理，因为当系统长时间处于非活动状态时会激活它。

系统可以进入的状态取决于底层平台，并且在不同的架构甚至同一架构的不同世代或系列之间也有所不同。然而，在大多数平台上通常可以找到四种睡眠状态。这些是挂起到空闲（也称为冻结），开机待机（待机），挂起到 RAM（内存）和挂起到磁盘（休眠）。它们有时也按照它们的 ACPI 状态来称呼：`S0`，`S1`，`S3`和`S4`，分别是：

```
# cat /sys/power/state
freeze mem disk standby
```

`CONFIG_SUSPEND`是必须设置的内核配置选项，以便系统支持系统的电源管理睡眠状态。也就是说，除了*冻结*之外，每个睡眠状态都是特定于平台的。因此，要支持剩下的三种状态中的任何一种，必须显式地向核心系统挂起子系统注册每种状态。然而，休眠的支持取决于其他内核配置选项，我们稍后会看到。

重要提示

因为只有用户知道系统何时不会被使用（甚至用户代码，如 GUI），系统电源管理操作总是从用户空间发起的。内核对此一无所知。这就是为什么本节的大部分内容都涉及`sysfs`和命令行的原因。

### 挂起到空闲（冻结）

这是最基本和轻量级的。这种状态纯粹由软件驱动，并涉及尽可能使 CPU 保持在最深的空闲状态。为了实现这一点，用户空间被冻结（所有用户空间任务都被冻结），并且所有 I/O 设备都被置于低功耗状态（可能低于运行时可用的功耗），以便处理器可以在其空闲状态下花费更多时间。以下是使系统处于空闲状态的命令：

```
$ echo freeze > /sys/power/state
```

前面的命令使系统处于空闲状态。因为它纯粹是软件，所以这种状态始终受支持（假设设置了`CONFIG_SUSPEND`内核配置选项）。这种状态可以用于不支持开机挂起或挂起到 RAM 的平台。然而，我们稍后会看到，它可以与挂起到 RAM 一起使用，以提供较低的恢复延迟。

重要提示

挂起到空闲等于冻结进程+挂起设备+空闲处理器

### 开机待机（待机或开机挂起）

除了冻结用户空间并将所有 I/O 设备置于低功耗状态之外，此状态执行的另一个操作是关闭所有非引导 CPU。以下是将系统置于待机状态的命令，假设平台支持：

```
$ echo standby > /sys/power/state
```

由于这种状态比冻结状态更进一步，因此相对于挂起到空闲状态，它也可以节省更多的能量，但是恢复延迟通常会大于冻结状态，尽管它相当低。

### 挂起到 RAM（挂起或 mem）

除了将系统中的所有内容置于低功耗状态之外，此状态通过关闭所有 CPU 并将内存置于自刷新状态进一步进行，以便其内容不会丢失，尽管根据平台的能力可能会执行其他操作。响应延迟高于待机，但仍然相当低。在此状态下，系统和设备状态被保存并保留在内存中。这就是为什么只有 RAM 是完全可操作的原因，因此状态名称为：

```
# echo mem > /sys/power/state
```

上述命令应该将系统置于挂起到 RAM 状态。然而，写入`mem`字符串时执行的真正操作由`/sys/power/mem_sleep`文件控制。该文件包含一个字符串列表，其中每个字符串代表系统在将`mem`写入`/sys/power/state`后可以进入的模式。虽然并非所有模式始终可用（这取决于平台），但可能的模式包括以下内容：

+   `s2idle`：这相当于挂起到空闲。因此，它始终可用。

+   `shallow`：这相当于待机挂起。其可用性取决于平台对待机模式的支持。

+   `deep`：这是真正的挂起到 RAM 状态，其可用性取决于平台。

查询内容的示例可以在此处看到：

```
$ cat /sys/power/mem_sleep
[s2idle] deep
```

所选模式用方括号`[ ]`括起来。如果某个模式不受平台支持，与之对应的字符串仍不会出现在`/sys/power/mem_sleep`中。将`/sys/power/mem_sleep`中的其他字符串之一写入其中会导致随后使用挂起模式更改为该字符串所代表的模式。

当系统启动时，默认的挂起模式（换句话说，不写入任何内容到`/sys/power/mem_sleep`）要么是`deep`（如果支持挂起到 RAM），要么是`s2idle`，但可以通过内核命令行中的`mem_sleep_default`参数的值来覆盖。

测试的一种方法是使用系统上可用的 RTC，假设它支持`唤醒闹钟`功能。您可以使用`ls /sys/class/rtc/`来识别系统上可用的 RTC。每个 RTC（换句话说，`rtc0`和`rtc1`）都会有一个目录。对于支持`alarm`功能的`rtc`，该`rtc`目录中将有一个`wakealarm`文件，可以按照以下方式使用它来配置闹钟，然后将系统挂起到 RAM：

```
/* No value returned means no alarms are set */
$ cat /sys/class/rtc/rtc0/wakealarm
/* Set the wakeup alarm for 20s */
# echo +20 > /sys/class/rtc/rtc0/wakealarm
/* Now Suspend system to RAM */ # echo mem > /sys/power/state
```

您应该在唤醒之前不会在控制台上看到进一步的活动。

### 挂起到磁盘（休眠）

这种状态由于尽可能关闭系统的大部分部分（包括内存）而实现了最大的节能。内存内容（快照）通常写入持久介质，通常是磁盘。之后，内存和整个系统都被关闭。在恢复时，快照被读回内存，并且系统从此休眠镜像引导。然而，这种状态也是最长的恢复时间，但仍然比执行完整的（重新）引导序列要快：

```
$ echo disk > /sys/power/state
```

一旦将内存状态写入磁盘，就可以执行多个操作。要执行的操作由`/sys/power/disk`文件及其内容控制。该文件包含一个字符串列表，其中每个字符串代表系统状态保存在持久存储介质上后可以执行的操作。可能的操作包括以下内容：

+   `platform`：自定义和特定于平台的，可能需要固件（BIOS）干预。

+   `shutdown`：关闭系统电源。

+   `reboot`：重新启动系统（主要用于诊断）。

+   `suspend`：将系统置于通过先前描述的`mem_sleep`文件选择的挂起睡眠状态。如果系统成功从该状态唤醒，那么休眠映像将被简单丢弃，一切将继续。否则，映像将用于恢复系统的先前状态。

+   `test_resume`：用于系统恢复诊断目的。加载镜像，就好像系统刚从休眠中醒来，当前运行的内核实例是一个恢复内核，并随后进行完整的系统恢复。

然而，给定平台上支持的操作取决于`/sys/power/disk`文件的内容：

```
$ cat /sys/power/disk
[platform] shutdown reboot suspend test_resume
```

所选操作用方括号`[ ]`括起来。将列出的字符串之一写入此文件会导致选择所代表的选项。休眠是如此复杂的操作，以至于它有自己的配置选项`CONFIG_HIBERNATION`。必须设置此选项才能启用休眠功能。也就是说，只有在给定 CPU 架构的支持包括系统恢复的低级代码时，才能设置此选项（参考`ARCH_HIBERNATION_POSSIBLE`内核配置选项）。

为了使挂起到磁盘工作，并且取决于休眠映像应存储在何处，磁盘上可能需要一个专用分区。这个分区也被称为交换分区。该分区用于将内存内容写入空闲交换空间。为了检查休眠是否按预期工作，通常尝试在`reboot`模式下进行休眠，如下所示：

```
$ echo reboot > /sys/power/disk 
# echo disk > /sys/power/state
```

第一个命令通知电源管理核心在创建休眠映像后应执行什么操作。在这种情况下，是重启。重启后，系统将从休眠映像中恢复，并且您应该回到您开始转换的命令提示符。这个测试的成功可能表明休眠很可能能够正确工作。也就是说，应该多次进行以加强测试。

现在我们已经完成了从运行系统管理睡眠状态，我们可以看看如何在驱动程序代码中实现其支持。

# 向设备驱动程序添加电源管理功能

设备驱动程序本身可以实现一个称为运行时电源管理的独特电源管理功能。并非所有设备都支持运行时电源管理。但是，那些支持的设备必须根据用户或系统的策略决定导出一些回调来控制它们的电源状态。正如我们之前所见，这是特定于设备的。在本节中，我们将学习如何通过电源管理支持扩展设备驱动程序功能。

尽管设备驱动程序提供运行时电源管理回调，但它们也通过提供另一组回调来便利和参与系统睡眠状态。每个集合都参与特定的系统睡眠状态。每当系统需要进入或从给定集合恢复时，内核将遍历为该状态提供回调的每个驱动程序，然后按照精确的顺序调用它们。简而言之，设备电源管理包括设备所处状态的描述，以及控制这些状态的机制。这是由内核提供的`struct dev_pm_ops`来实现的，每个对电源管理感兴趣的设备驱动程序/类/总线都必须填充。这允许内核与系统中的每个设备通信，而不管设备所在的总线或所属的类是什么。让我们退一步，记住`struct device`是什么样子的：

```
struct device {
    [...]
    struct device *parent;
    struct bus_type *bus;
    struct device_driver *driver;
    struct dev_pm_info power;
    struct dev_pm_domain *pm_domain;
}
```

在前面的`struct device`数据结构中，我们可以看到设备可以是子设备（其`.parent`字段指向另一个设备）或设备父级（当另一个设备的`.parent`字段指向它时），可以位于给定总线后面，或者可以属于给定类，或者可以间接属于给定子系统。此外，我们可以看到设备可以是给定电源域的一部分。`.power`字段是`struct dev_pm_info`类型。它主要保存与电源管理相关的状态，例如当前电源状态，是否可以唤醒，是否已准备好，是否已挂起。由于涉及的内容如此之多，我们将在使用它们时详细解释这些内容。

为了使设备能够参与电源管理，无论是在子系统级别还是在设备驱动程序级别，它们的驱动程序都需要通过定义和填充`include/linux/pm.h`中定义的`struct dev_pm_ops`类型的对象来实现一组设备电源管理操作，如下所示：

```
struct dev_pm_ops {
    int (*prepare)(struct device *dev);
    void (*complete)(struct device *dev);
    int (*suspend)(struct device *dev);
    int (*resume)(struct device *dev);
    int (*freeze)(struct device *dev);
    int (*thaw)(struct device *dev);
    int (*poweroff)(struct device *dev);
    int (*restore)(struct device *dev);
    [...]
    int (*suspend_noirq)(struct device *dev);
    int (*resume_noirq)(struct device *dev);
    int (*freeze_noirq)(struct device *dev);
    int (*thaw_noirq)(struct device *dev);
    int (*poweroff_noirq)(struct device *dev);
    int (*restore_noirq)(struct device *dev);
    int (*runtime_suspend)(struct device *dev);
    int (*runtime_resume)(struct device *dev);
    int (*runtime_idle)(struct device *dev);
};
```

在前面的数据结构中，`*_early()`和`*_late()`回调已被删除以提高可读性。我建议您查看完整的定义。也就是说，鉴于其中的大量回调，我们将在本章的各个部分中逐步描述它们的使用。

重要提示

设备电源状态有时被称为*D*状态，受 PCI 设备和 ACPI 规范的启发。这些状态从`D0`到`D3`，包括。尽管并非所有设备类型都以这种方式定义电源状态，但这种表示可以映射到所有已知的设备类型。

## 实现运行时电源管理能力

运行时电源管理是一种每设备的电源管理功能，允许特定设备在系统运行时控制其状态，而不受全局系统的影响。为了实现运行时电源管理，驱动程序应该只提供`struct dev_pm_ops`中的部分回调函数，如下所示：

```
struct dev_pm_ops {
    [...]
    int (*runtime_suspend)(struct device *dev);
    int (*runtime_resume)(struct device *dev);
    int (*runtime_idle)(struct device *dev);
};
```

内核还提供了`SET_RUNTIME_PM_OPS()`，它接受要填充到结构中的三个回调。此宏定义如下：

```
#define SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
        .runtime_suspend = suspend_fn, \
        .runtime_resume = resume_fn, \
        .runtime_idle = idle_fn,
```

前面的回调是运行时电源管理中涉及的唯一回调，以下是它们必须执行的描述：

+   如果需要，`.runtime_suspend()`必须记录设备的当前状态并将设备置于静止状态。当设备未被使用时，PM 将调用此方法。在其简单形式中，此方法必须将设备置于一种状态，使其无法与 CPU 和 RAM 通信。

+   当设备必须处于完全功能状态时，将调用`.runtime_resume()`。如果系统需要访问此设备，可能会出现这种情况。此方法必须恢复电源并重新加载任何所需的设备状态。

+   当设备不再使用时（实际上是当其达到`0`时），将调用`.runtime_idle()`，以及活动子设备的数量。但是，此回调执行的操作是特定于驱动程序的。在大多数情况下，如果满足某些条件，驱动程序会在设备上调用`runtime_suspend()`，或者调用`pm_schedule_suspend()`（给定延迟以设置定时器以在将来提交挂起请求），或者调用`pm_runtime_autosuspend()`（根据已使用`pm_runtime_set_autosuspend_delay()`设置的延迟来安排将来的挂起请求）。如果`.runtime_idle`回调不存在，或者返回`0`，PM 核心将立即调用`.runtime_suspend()`回调。对于 PM 核心不执行任何操作，`.runtime_idle()`必须返回非零值。驱动程序通常会在这种情况下返回`-EBUSY`或`1`。

在实现了回调之后，它们可以被填充到`struct dev_pm_ops`中，如下例所示：

```
static const struct dev_pm_ops bh1780_dev_pm_ops = {
    SET_SYSTEM_SLEEP_PM_OPS(pm_runtime_force_suspend,
                            pm_runtime_force_resume)
    SET_RUNTIME_PM_OPS(bh1780_runtime_suspend,
                           bh1780_runtime_resume, NULL)
};
[...]
static struct i2c_driver bh1780_driver = {
    .probe = bh1780_probe,
    .remove = bh1780_remove,
    .id_table = bh1780_id,
    .driver = {
        .name = “bh1780”,
        .pm = &bh1780_dev_pm_ops,
        .of_match_table = of_match_ptr(of_bh1780_match),
    },
};
module_i2c_driver(bh1780_driver);
```

上述是来自`drivers/iio/light/bh1780.c`的摘录，这是一个 IIO 环境光传感器驱动程序。在这段摘录中，我们可以看到如何使用方便的宏来填充`struct dev_pm_ops`。在这里使用`SET_SYSTEM_SLEEP_PM_OPS`来填充与系统睡眠相关的宏，我们将在接下来的部分中看到。`pm_runtime_force_suspend`和`pm_runtime_force_resume`是 PM 核心公开的特殊辅助函数，用于强制设备挂起和恢复。

### 驱动程序中的运行时 PM

事实上，PM 核心使用两个计数器跟踪每个设备的活动情况。第一个计数器是`power.usage_count`，它计算对设备的活动引用。这些可能是外部引用，例如打开的文件句柄，或者正在使用此设备的其他设备，或者它们可能是用于在操作期间保持设备活动的内部引用。另一个计数器是`power.child_count`，它计算活动的子设备数量。

这些计数器定义了从 PM 角度看给定设备的活动/空闲状态。设备的活动/空闲状态是 PM 核心确定设备是否可访问的唯一可靠手段。空闲状态是指设备使用计数递减至`0`，而活动状态（也称为恢复状态）发生在设备使用计数递增时。

在空闲状态下，PM 核心发送/执行空闲通知（即将设备的`power.idle_notification`字段设置为`true`，调用总线类型/类/设备`->runtime_idle()`回调，并将`.idle_notification`字段再次设置为`false`）以检查设备是否可以挂起。如果`->runtime_idle()`回调不存在或者返回`0`，PM 核心将立即调用`->runtime_suspend()`回调来挂起设备，之后设备的`power.runtime_status`字段将设置为`RPM_SUSPENDED`，这意味着设备已挂起。在恢复条件下（设备使用计数增加），PM 核心将在特定条件下同步或异步地恢复此设备。请查看`drivers/base/power/runtime.c`中的`rpm_resume()`函数及其描述。

最初，所有设备的运行时 PM 都被禁用。这意味着在为设备调用`pm_runtime_enable()`之前，对设备调用大多数与 PM 相关的辅助函数将失败，这将启用此设备的运行时 PM。尽管所有设备的初始运行时 PM 状态都是挂起的，但它不需要反映设备的实际物理状态。因此，如果设备最初是活动的（换句话说，它能够处理 I/O），则必须使用`pm_runtime_set_active()`（它将设置`power.runtime_status`为`RPM_ACTIVE`）来将其运行时 PM 状态更改为活动状态，并且如果可能的话，必须在为设备调用`pm_runtime_enable()`之前使用`pm_runtime_get_noresume()`增加其使用计数。一旦设备完全初始化，就可以对其调用`pm_runtime_put()`。

在这里调用`pm_runtime_get_noresume()`的原因是，如果调用了`pm_runtime_put()`，设备的使用计数将回到零，这对应于空闲状态，然后将进行空闲通知。此时，您可以检查是否满足必要条件并挂起设备。但是，如果初始设备状态为*禁用*，则无需这样做。

还有`pm_runtime_get()`、`pm_runtime_get_sync()`、`pm_runtime_put_noidle()`和`pm_runtime_put_sync()`辅助程序。`pm_runtime_get_sync()`、`pm_runtime_get()`和`pm_runtime_get_noresume()`之间的区别在于，前者在增加设备使用计数后，如果匹配了活动/恢复条件，将同步（立即）执行设备的恢复，而第二个辅助程序将异步执行（提交请求）。第三个和最后一个在减少设备使用计数后立即返回（甚至不检查恢复条件）。相同的机制适用于`pm_runtime_put_sync()`、`pm_runtime_put()`和`pm_runtime_put_noidle()`。

给定设备的活动子级数量会影响该设备的使用计数。通常，需要父级才能访问子级，因此在子级活动时关闭父级将是适得其反的。然而，有时可能需要忽略设备的活动子级，以确定该设备是否处于空闲状态。一个很好的例子是 I2C 总线，在这种情况下，总线可以在总线上的设备（子级）活动时报告为空闲。对于这种情况，可以调用`pm_suspend_ignore_children()`来允许设备在具有活动子级时报告为空闲。

#### 运行时 PM 同步和异步操作

在前面的部分中，我们介绍了 PM 核心可以执行同步或异步 PM 操作的事实。对于同步操作，事情很简单（方法调用是串行的），但是在 PM 上下文中异步调用时，我们需要注意执行哪些步骤。

你应该记住，在异步模式下，提交动作的请求而不是立即调用此动作的处理程序。它的工作方式如下：

1.  PM 核心将设备的`power.request`字段（类型为`enum rpm_request`）设置为要提交的请求类型（换句话说，对于空闲通知请求为`RPM_REQ_IDLE`，对于挂起请求为`RPM_REQ_SUSPEND`，对于自动挂起请求为`RPM_REQ_AUTOSUSPEND`），这对应于要执行的动作。

1.  PM 核心将设备的`power.request_pending`字段设置为`true`。

1.  PM 核心队列（计划稍后执行）设备的 RPM 相关工作（`power.work`，其工作函数为`pm_runtime_work()`；请参阅`pm_runtime_init()`，其中初始化了该工作）在全局 PM 相关工作队列中。

1.  当这项工作有机会运行时，工作函数（即`pm_runtime_work()`）将首先检查设备上是否仍有待处理的请求（`if (dev->power.request_pending)`），并根据设备的`power.request_pending`字段执行`switch ... case`以调用底层请求处理程序。

请注意，工作队列管理自己的线程，可以运行计划的工作。因为在异步模式下，处理程序被安排在工作队列中，异步 PM 相关的辅助程序完全可以在原子上下文中调用。例如，在 IRQ 处理程序中调用，相当于推迟 PM 请求处理。

#### 自动挂起

自动挂起是由不希望设备在运行时一旦空闲就挂起的驱动程序使用的机制，而是希望设备在一定的最短时间内保持不活动。

在 RPM 的背景下，术语*autosuspend*并不意味着设备会自动挂起自己。相反，它是基于一个定时器，当定时器到期时，将排队一个挂起请求。这个定时器实际上是设备的`power.suspend_timer`字段（请参阅`pm_runtime_init()`，在那里它被设置）。调用`pm_runtime_put_autosuspend()`将启动定时器，而`pm_runtime_set_autosuspend_delay()`将设置超时（尽管可以通过`sysfs`中的`/sys/devices/.../power/autosuspend_delay_ms`属性设置）。

`pm_schedule_suspend()`辅助程序也可以使用这个定时器，带有延迟参数（在这种情况下，它将优先于`power.autosuspend_delay`字段中设置的延迟），之后将提交一个挂起请求。您可以将这个定时器视为可以用来在计数器达到零和设备被视为空闲之间添加延迟的东西。这对于开关成本很高的设备非常有用。

为了使用`autosuspend`，子系统或驱动程序必须调用`pm_runtime_use_autosuspend()`（最好在注册设备之前）。这个辅助程序将把设备的`power.use_autosuspend`字段设置为`true`。在启用了 autosuspend 的设备上调用`pm_runtime_mark_last_busy()`，这样它就可以将`power.last_busy`字段设置为当前时间（以`jiffies`为单位），因为这个字段用于计算 autosuspend 的空闲期（例如，`new_expire_time = last_busy + msecs_to_jiffies(autosuspend_delay)`）。

考虑到引入的所有运行时 PM 概念，现在让我们把所有东西放在一起，看看在一个真实的驱动程序中是如何完成的。

### 把所有东西放在一起

在没有真实案例研究的情况下，对运行时 PM 核心的理论研究将变得不那么重要。现在是时候看看之前的概念是如何应用的。对于这个案例研究，我们将选择 Linux 驱动程序`bh1780`，它是 Linux 内核源代码中的`drivers/iio/light/bh1780.c`。

首先，让我们看一下`probe`方法的摘录：

```
static int bh1780_probe(struct i2c_client *client,
                        const struct i2c_device_id *id)
{
    [...]
    /* Power up the device */ [...]
    pm_runtime_get_noresume(&client->dev);
    pm_runtime_set_active(&client->dev);
    pm_runtime_enable(&client->dev);
    ret = bh1780_read(bh1780, BH1780_REG_PARTID);
    dev_info(&client->dev, “Ambient Light Sensor, Rev : %lu\n”,
                 (ret & BH1780_REVMASK));
    /*
     * As the device takes 250 ms to even come up with a fresh
     * measurement after power-on, do not shut it down      * unnecessarily.
     * Set autosuspend to five seconds.
     */
    pm_runtime_set_autosuspend_delay(&client->dev, 5000);
    pm_runtime_use_autosuspend(&client->dev);
    pm_runtime_put(&client->dev);
    [...]
    ret = iio_device_register(indio_dev);
    if (ret)
        goto out_disable_pm; return 0;
out_disable_pm:
    pm_runtime_put_noidle(&client->dev);
    pm_runtime_disable(&client->dev); return ret;
}
```

在前面的片段中，为了便于阅读，只留下了与电源管理相关的调用。首先，`pm_runtime_get_noresume()`将增加设备的使用计数，而不携带设备的空闲通知（`_noidle`后缀）。您可以使用`pm_runtime_get_noresume()`接口关闭运行时挂起功能，或者在设备挂起时使使用计数为正，以避免由于运行时挂起而无法正常唤醒的问题。然后，在驱动程序中的下一行是`pm_runtime_set_active()`。这个辅助程序将设备标记为活动的（`power.runtime_status = RPM_ACTIVE`），并清除设备的`power.runtime_error`字段。此外，设备父级的未挂起（活动）子级计数将被修改以反映新的状态（实际上是增加）。在设备上调用`pm_runtime_set_active()`将阻止该设备的父级在运行时挂起（假设父级的运行时 PM 已启用），除非父级的`power.ignore_children`标志已设置。因此，一旦为设备调用了`pm_runtime_set_active()`，就应该尽快为其调用`pm_runtime_enable()`。调用这个函数并不是强制性的；它必须与 PM 核心和设备的状态保持一致，假设初始状态是`RPM_SUSPENDED`。

重要说明

`pm_runtime_set_active()`的相反操作是`pm_runtime_set_suspended()`，它将设备状态更改为`RPM_SUSPENDED`，并减少父级的活动子级计数。提交父级的空闲通知请求。

`pm_runtime_enable()`是强制的运行时 PM 助手，它启用设备的运行时 PM，即在设备的`power.disable_depth`值大于`0`时递减该值。需要注意的是，每次运行时 PM 助手调用时都会检查设备的`power.disable_depth`值，该值必须为`0`才能继续执行。其初始值为`1`，并且在调用`pm_runtime_enable()`时递减该值。在错误路径上，会调用`pm_runtime_put_noidle()`以使 PM 运行时计数平衡，并且`pm_runtime_disable()`会完全禁用设备的运行时 PM。

正如你可能已经猜到的，这个驱动程序也处理 IIO 框架，这意味着它在 sysfs 中公开了与其物理转换通道对应的条目。读取与通道对应的 sysfs 文件将报告该通道产生的转换的数字值。然而，对于`bh1780`，其驱动程序中的通道读取入口点是`bh1780_read_raw()`。该方法的摘录如下：

```
static int bh1780_read_raw(struct iio_dev *indio_dev,
                           struct iio_chan_spec const *chan,
                           int *val, int *val2, long mask)
{
    struct bh1780_data *bh1780 = iio_priv(indio_dev);
    int value;
    switch (mask) {
    case IIO_CHAN_INFO_RAW:
        switch (chan->type) {
        case IIO_LIGHT:
            pm_runtime_get_sync(&bh1780->client->dev);
            value = bh1780_read_word(bh1780, BH1780_REG_DLOW);
            if (value < 0)
                return value;
            pm_runtime_mark_last_busy(&bh1780->client->dev); 
            pm_runtime_put_autosuspend(&bh1780->client->dev);
            *val = value;
            return IIO_VAL_INT;
        default:
            return -EINVAL;
    case IIO_CHAN_INFO_INT_TIME:
        *val = 0;
        *val2 = BH1780_INTERVAL * 1000;
        return IIO_VAL_INT_PLUS_MICRO;
    default:
        return -EINVAL;
    }
}
```

同样，只有与运行时 PM 相关的函数调用值得我们关注。在通道读取时，会调用前面的函数。设备驱动程序必须指示设备对通道进行采样，执行转换，其结果将由设备驱动程序读取并报告给读取者。问题在于，设备可能处于挂起状态。因此，因为驱动程序需要立即访问设备，驱动程序在设备上调用`pm_runtime_get_sync()`。如果你还记得的话，这个方法会增加设备的使用计数，并进行同步（`_sync`后缀）恢复设备。设备恢复后，驱动程序可以与设备通信并读取转换值。因为驱动程序支持自动挂起，所以会调用`pm_runtime_mark_last_busy()`以标记设备最后活动的时间。这将更新用于自动挂起的定时器的超时值。最后，驱动程序调用`pm_runtime_put_autosuspend()`，这将在自动挂起定时器到期后执行设备的运行时挂起，除非该定时器在到期前由`pm_runtime_mark_last_busy()`在某处被调用重新启动，或者在再次进入读取函数（例如在 sysfs 中读取通道）之前到期。

总之，在访问硬件之前，驱动程序可以使用`pm_runtime_get_sync()`恢复设备，当完成硬件操作后，驱动程序可以使用`pm_runtime_put_sync()`、`pm_runtime_put()`或`pm_runtime_put_autosuspend()`通知设备处于空闲状态（假设启用了自动挂起，在这种情况下，必须先调用`pm_runtime_mark_last_busy()`以更新自动挂起定时器的超时）。

最后，让我们专注于模块被卸载时调用的方法。以下是一个摘录，其中只有与电源管理相关的调用是感兴趣的：

```
static int bh1780_remove(struct i2c_client *client)
{
    int ret;
    struct iio_dev *indio_dev = i2c_get_clientdata(client);
    struct bh1780_data *bh1780 = iio_priv(indio_dev);
    iio_device_unregister(indio_dev);
    pm_runtime_get_sync(&client->dev);
    pm_runtime_put_noidle(&client->dev);
    pm_runtime_disable(&client->dev);
    ret = bh1780_write(bh1780, BH1780_REG_CONTROL,                        BH1780_POFF);
    if (ret < 0) {
        dev_err(&client->dev, “failed to power off\n”);
        return ret;
    }
    return 0;
}
```

这里调用的第一个运行时 PM 方法是`pm_runtime_get_sync()`。这个调用让我们猜测设备将要被使用，也就是说，驱动程序需要访问硬件。因此，这个辅助函数立即恢复设备（实际上增加了设备的使用计数并进行了同步恢复设备）。之后，调用`pm_runtime_put_noidle()`以减少设备使用计数而不进行空闲通知。接下来，调用`pm_runtime_disable()`以在设备上禁用运行时 PM。这将增加设备的`power.disable_depth`，如果之前为零，则取消设备的所有挂起运行时 PM 请求，并等待所有正在进行的操作完成，因此从 PM 核心的角度来看，设备不再存在（请记住，`power.disable_depth`将不匹配 PM 核心的期望，这意味着在此设备上调用的任何进一步的运行时 PM 辅助函数将失败）。最后，通过 i2c 命令关闭设备，之后其硬件状态将反映其运行时 PM 状态。

以下是适用于运行时 PM 回调和执行的一般规则：

+   `->runtime_idle()`和`->runtime_suspend()`只能为活动设备（状态为活动）执行。

+   `->runtime_idle()`和`->runtime_suspend()`只能为使用计数为零的设备执行，并且子设备的活动计数为零，或者设置了`power.ignore_children`标志。

+   `->runtime_resume()`只能为挂起的设备（状态为*挂起*）执行。

此外，PM 核心提供的辅助函数遵守以下规则：

+   如果`->runtime_suspend()`即将被执行，或者有一个挂起的请求要执行它，`->runtime_idle()`将不会为同一设备执行。

+   执行或计划执行`->runtime_suspend()`的请求将取消执行同一设备的`->runtime_idle()`的任何挂起请求。

+   如果`->runtime_resume()`即将被执行，或者有一个挂起的请求要执行它，其他回调将不会为同一设备执行。

+   执行`->runtime_resume()`的请求将取消执行同一设备的其他回调的任何挂起或计划请求，除了计划的自动挂起。

上述规则是这些回调的任何调用可能失败的很好的指标。从中我们还可以观察到，恢复或请求恢复优于任何其他回调或请求。

### 电源域的概念

从技术上讲，电源域是一组共享电源资源（例如时钟或电源平面）的设备。从内核的角度来看，电源域是一组使用相同的回调和子系统级别的公共 PM 数据的设备集合。从硬件的角度来看，电源域是一个用于管理电压相关的设备的硬件概念；例如，视频核心 IP 与显示 IP 共享一个电源轨。

由于 SoC 设计变得更加复杂，需要找到一种抽象方法，使驱动程序尽可能通用；然后，`genpd`出现了。这代表通用电源域。它是 Linux 内核的一个抽象，将每个设备的运行时电源管理扩展到共享电源轨的设备组。此外，电源域被定义为设备树的一部分，其中描述了设备和电源控制器之间的关系。这允许电源域在运行时重新设计，并且驱动程序可以适应而无需重新启动整个系统或重新构建新的内核。

它被设计成如果设备存在电源域对象，则其 PM 回调优先于总线类型（或设备类或类型）回调。有关此的通用文档可在内核源代码的`Documentation/devicetree/bindings/power/power_domain.txt`中找到，与您的 SoC 相关的文档可以在同一目录中找到。

## 系统挂起和恢复序列

`struct dev_pm_ops`数据结构的引入在某种程度上促进了对 PM 核心在挂起或恢复阶段执行的步骤和操作的理解，可以总结如下：

```
“prepare —> Suspend —> suspend_late —> suspend_noirq”
          |---------- Wakeup ----------|
“resume_noirq —> resume_early —> resume -> complete”
```

上述是完整的系统 PM 链，列在`include/linux/suspend.h`中定义的`enum suspend_stat_step`中。这个流程应该让你想起`struct dev_pm_ops`数据结构。

在 Linux 内核代码中，`enter_state()`是由系统电源管理核心调用的函数，用于进入系统睡眠状态。现在让我们花一些时间了解系统挂起和恢复期间真正发生了什么。

### 挂起阶段

在挂起时，`enter_state()`经历的步骤如下：

1.  如果内核配置选项`CONFIG_SUSPEND_SKIP_SYNC`未设置，则首先在文件系统上调用`sync()`（参见`ksys_sync()`）。

1.  调用挂起通知器（当用户空间仍然存在时）。参考`register_pm_notifier()`，这是用于注册它们的辅助程序。

1.  它冻结任务（参见`suspend_freeze_processes()`），这会冻结用户空间以及内核线程。如果内核配置中未设置`CONFIG_SUSPEND_FREEZER`，则会跳过此步骤。

1.  通过调用驱动程序注册的每个`.suspend()`回调来挂起设备。这是挂起的第一阶段（参见`suspend_devices_and_enter()`）。

1.  它禁用设备中断（参见`suspend_device_irqs()`）。这可以防止设备驱动程序接收中断。

1.  然后，发生设备挂起的第二阶段（调用`.suspend_noirq`回调）。这一步被称为*noirq*阶段。

1.  它禁用非引导 CPU（使用 CPU 热插拔）。在它们下线之前，CPU 调度程序被告知不要在这些 CPU 上安排任何任务（参见`disable_nonboot_cpus()`）。

1.  关闭中断。

1.  执行系统核心回调（参见`syscore_suspend()`）。

1.  它让系统进入睡眠状态。

这是系统进入睡眠状态之前执行的操作的粗略描述。某些操作的行为可能会根据系统即将进入的睡眠状态略有不同。

### 恢复阶段

一旦系统被挂起（无论有多深），一旦发生唤醒事件，系统就需要恢复。以下是 PM 核心执行的唤醒系统的步骤和操作：

1.  （唤醒信号。）

1.  运行 CPU 的唤醒代码。

1.  执行系统核心回调。

1.  打开中断。

1.  启用非引导 CPU（使用 CPU 热插拔）。

1.  恢复设备的第一阶段（`.resume_noirq()`回调）。

1.  启用设备中断。

1.  挂起设备的第二阶段（`.resume()`回调）。

1.  解冻任务。

1.  调用通知器（当用户空间恢复时）。

我会让你在 PM 代码中发现在恢复过程的每个步骤中调用了哪些函数。然而，从驱动程序内部来看，这些步骤都是透明的。驱动程序唯一需要做的就是根据希望参与的步骤填充`struct dev_pm_ops`中的适当回调，我们将在下一节中看到。

## 实现系统睡眠功能

系统睡眠和运行时 PM 是不同的东西，尽管它们彼此相关。有些情况下，通过不同的方式进行操作，它们会将系统带到相同的物理状态。因此，通常不建议用一个替换另一个。

我们已经看到设备驱动程序如何通过根据它们需要参与的睡眠状态在`struct dev_pm_ops`数据结构中填充一些回调来参与系统休眠。无论睡眠状态如何，通常提供的回调都是`.suspend`、`.resume`、`.freeze`、`.thaw`、`.poweroff`和`.restore`。它们是相当通用的回调，定义如下：

+   .suspend：在将系统置于保留主存储器内容的睡眠状态之前执行此操作。

+   .resume：在从保留主存储器内容的睡眠状态唤醒系统后调用此回调，此时设备的状态取决于设备所属的平台和子系统。

+   .freeze：特定于休眠，此回调在创建休眠镜像之前执行。它类似于`.suspend`，但不应该使设备发出唤醒事件或更改其电源状态。大多数实现此回调的设备驱动程序只需将设备设置保存在内存中，以便在随后的休眠恢复中可以重新使用。

+   .thaw：这是特定于休眠的回调，在创建休眠镜像后执行，或者如果创建镜像失败，则执行。在尝试从这样的镜像中恢复主存储器的内容失败后，也会执行。它必须撤消前面`.freeze`所做的更改，以使设备以与调用`.freeze`之前相同的方式运行。

+   .poweroff：也是特定于休眠，此回调在保存休眠镜像后执行。它类似于`.suspend`，但不需要在内存中保存设备的设置。

+   .restore：这是最后一个特定于休眠的回调，在从休眠镜像中恢复主存储器的内容后执行。它类似于`.resume`。

大多数前面的回调都是相似的，或者执行大致相似的操作。虽然`.resume`、`.thaw`和`.restore`三者可能执行类似的任务，但对于另一个三者——`->suspend`、`->freeze`和`->poweroff`也是如此。因此，为了提高代码可读性或简化回调填充，PM 核心提供了`SET_SYSTEM_SLEEP_PM_OPS`宏，它接受`suspend`和`resume`函数，并填充系统相关的 PM 回调如下：

```
#define SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
        .suspend = suspend_fn, \
        .resume = resume_fn, \
        .freeze = suspend_fn, \
        .thaw = resume_fn, \
        .poweroff = suspend_fn, \
        .restore = resume_fn,
```

与`_noirq()`相关的回调也是如此。如果驱动程序只需要参与系统挂起的`noirq`阶段，则可以使用`SET_NOIRQ_SYSTEM_SLEEP_PM_OPS`宏，以便自动填充`struct dev_pm_ops`数据结构中的`_noirq()`相关回调。以下是该宏的定义：

```
#define SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
        .suspend_noirq = suspend_fn, \
        .resume_noirq = resume_fn, \
        .freeze_noirq = suspend_fn, \
        .thaw_noirq = resume_fn, \
        .poweroff_noirq = suspend_fn, \
        .restore_noirq = resume_fn,
```

前面的宏只有两个参数，就像前面的宏一样，表示这次是`noirq`阶段的`suspend`和`resume`回调。您应该记住，这些回调在系统上禁用 IRQ 时被调用。

最后，还有`SET_LATE_SYSTEM_SLEEP_PM_OPS`宏，它将`->suspend_late`、`->freeze_late`和`->poweroff_late`指向相同的函数，反之亦然，将`->resume_early`、`->thaw_early`和`->restore_early`指向相同的函数：

```
#define SET_LATE_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
        .suspend_late = suspend_fn, \
        .resume_early = resume_fn, \
        .freeze_late = suspend_fn, \
        .thaw_early = resume_fn, \
        .poweroff_late = suspend_fn, \
        .restore_early = resume_fn,
```

除了减少编码工作外，所有前面的宏都受到`#ifdef CONFIG_PM_SLEEP`内核配置选项的限制，以便在不需要 PM 的情况下不构建它们。最后，如果要将相同的挂起和恢复回调用于挂起到 RAM 和休眠，可以使用以下命令：

```
#define SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
const struct dev_pm_ops name = { \
    SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
}
```

在上面的片段中，`name`表示设备 PM 操作结构的实例化名称。`suspend_fn`和`resume_fn`是在系统进入挂起状态或从睡眠状态恢复时要调用的回调。

现在我们能够在驱动程序代码中实现系统休眠功能，让我们看看如何行为系统唤醒源，允许退出睡眠状态。

# 成为系统唤醒源

PM 核心允许系统在系统暂停后被唤醒。能够唤醒系统的设备在 PM 语言中被称为**唤醒源**。为了使唤醒源正常工作，它需要一个所谓的**唤醒事件**，大多数情况下，这被等同于 IRQ 线。换句话说，唤醒源生成唤醒事件。当唤醒源生成唤醒事件时，通过唤醒事件框架提供的接口将唤醒源设置为激活状态。当事件处理结束时，它被设置为非激活状态。激活和停用之间的间隔表示事件正在被处理。在本节中，我们将看到如何在驱动程序代码中使您的设备成为系统唤醒源。

唤醒源的工作方式是，当系统中有任何唤醒事件正在被处理时，不允许暂停。如果暂停正在进行，它将被终止。内核通过`struct wakeup_source`来抽象唤醒源，该结构也用于收集与它们相关的统计信息。以下是`include/linux/pm_wakeup.h`中此数据结构的定义：

```
struct wakeup_source {
    const char *name;
    struct list_head entry;
    spinlock_t lock;
    struct wake_irq *wakeirq;
    struct timer_list timer;
    unsigned long timer_expires;
    ktime_t total_time;
    ktime_t max_time;
    ktime_t last_time;
    ktime_t start_prevent_time;
    ktime_t prevent_sleep_time;
    unsigned long event_count;
    unsigned long active_count;
    unsigned long relax_count;
    unsigned long expire_count;
   unsigned long wakeup_count;
    bool active:1;
    bool autosleep_enabled:1;
};
```

这个结构对于您的代码来说是完全无用的，但是研究它将有助于您理解`sysfs`属性的唤醒源的含义：

+   `entry`用于在链表中跟踪所有唤醒源。

+   `计时器`与`timer_expires`密切相关。当唤醒源生成唤醒事件并且该事件正在被处理时，唤醒源被称为*活动的*，这会阻止系统暂停。处理完唤醒事件后（系统不再需要为此目的处于活动状态），它将恢复为非活动状态。驱动程序可以执行激活和停用操作，也可以通过在激活期间指定超时来决定其他操作。这个超时将被 PM 唤醒核心用来配置一个定时器，在超时后自动将事件设置为非活动状态。`timer`和`timer_expires`就是用于这个目的。

+   `total_time`是这个唤醒源处于活动状态的总时间。它总结了唤醒源在活动状态下花费的总时间。这是设备繁忙水平和功耗水平的良好指标。

+   `max_time`是唤醒源保持（或连续）处于活动状态的最长时间。时间越长，异常性就越大。

+   `last_time`表示此唤醒源上次活动的开始时间。

+   `start_prevent_time`是唤醒源开始阻止系统自动休眠的时间点。

+   `prevent_sleep_time`是这个唤醒源阻止系统自动休眠的总时间。

+   `event_count`表示唤醒源报告的事件数量。换句话说，它表示被触发的唤醒事件的数量。

+   `active_count`表示唤醒源被激活的次数。在某些情况下，这个值可能不相关或不一致。例如，当唤醒事件发生时，唤醒源需要切换到激活状态。但这并不总是这样，因为事件可能发生在唤醒源已经被激活的情况下。因此`active_count`可能小于`event_count`，在这种情况下，这可能意味着在上一个唤醒事件被处理完之前，很可能另一个唤醒事件被生成。这在一定程度上反映了唤醒源所代表的设备的繁忙程度。

+   `relax_count`表示唤醒源被停用的次数。

+   `expire_count`表示唤醒源超时的次数。

+   `wakeup_count`是唤醒源终止挂起过程的次数。如果唤醒源在挂起过程中生成唤醒事件，挂起过程将被中止。此变量记录了唤醒源终止挂起过程的次数。这可能是检查系统是否总是无法挂起的良好指标。

+   `active`表示唤醒源的激活状态。

+   对于我来说，`autosleep_enabled`记录了系统的自动睡眠状态，无论它是否启用。

为了使设备成为唤醒源，其驱动程序必须调用`device_init_wakeup()`。此函数设置设备的`power.can_wakeup`标志（以便`device_can_wakeup()`助手返回当前设备作为唤醒源的能力），并将其唤醒相关属性添加到 sysfs。此外，它创建一个唤醒源对象，注册它，并将其附加到设备（`dev->power.wakeup`）。但是，`device_init_wakeup()`只会将设备变成一个具有唤醒功能的设备，而不会为其分配唤醒事件。

重要提示

请注意，只有具有唤醒功能的设备才会在 sysfs 中有一个 power 目录，提供所有唤醒信息。

为了分配唤醒事件，驱动程序必须调用`enable_irq_wake()`，并将用作唤醒事件的 IRQ 线作为参数。`enable_irq_wake()`的功能可能是特定于平台的（除其他功能外，它还调用底层 irqchip 驱动程序公开的`irq_chip.irq_set_wake`回调）。除了打开处理给定 IRQ 作为系统唤醒中断线的平台逻辑外，它还指示`suspend_device_irqs()`（在系统挂起路径上调用：参考*Suspend stages*部分，*step 5*）以不同方式处理给定的 IRQ。因此，IRQ 将保持启用状态，直到下一个中断，然后将被禁用，标记为挂起，并暂停，以便在随后的系统恢复期间由`resume_device_irqs()`重新启用。这使得驱动程序的`->suspend`方法成为调用`enable_irq_wake()`的正确位置，以便在正确时刻始终重新激活唤醒事件。另一方面，驱动程序的`->resume`回调是调用`disable_irq_wake()`的正确位置，该回调将关闭 IRQ 的系统唤醒功能的平台配置。

设备作为唤醒源的能力是硬件问题，唤醒能力设备是否应发出唤醒事件是一项政策决定，并由用户空间通过`sysfs`属性`/sys/devices/.../power/wakeup`进行管理。此文件允许用户空间检查或决定设备（通过其唤醒事件）是否能够唤醒系统从睡眠状态中唤醒。此文件可以读取和写入。读取时，可以返回`enabled`或`disabled`。如果返回`enabled`，这意味着设备能够发出事件；如果返回`disabled`，这意味着设备无法这样做。向其写入`enabled`或`disabled`字符串将指示设备是否应该信号系统唤醒（内核`device_may_wakeup()`助手将分别返回`true`或`false`）。请注意，对于无法生成系统唤醒事件的设备，此文件不存在。

让我们看一个例子，看看驱动程序如何利用设备的唤醒功能。以下是`i.MX6 SNVS` powerkey 驱动程序的摘录，位于`drivers/input/keyboard/snvs_pwrkey.c`中：

```
static int imx_snvs_pwrkey_probe(struct platform_device *pdev)
{
    [...]
    error = devm_request_irq(&pdev->dev, pdata->irq,
    imx_snvs_pwrkey_interrupt, 0, pdev->name, pdev);
    pdata->wakeup = of_property_read_bool(np, “wakeup-source”); 
    [...]
    device_init_wakeup(&pdev->dev, pdata->wakeup);
    return 0;
}
static int
    maybe_unused imx_snvs_pwrkey_suspend(struct device *dev)
{
    [...]
    if (device_may_wakeup(&pdev->dev))
        enable_irq_wake(pdata->irq);
    return 0;
}
static int maybe_unused imx_snvs_pwrkey_resume(struct                                                device *dev)
{
    [...]
    if (device_may_wakeup(&pdev->dev))
        disable_irq_wake(pdata->irq);
    return 0;
}
```

在上面的代码摘录中，从上到下，我们有驱动程序探测方法，首先使用`device_init_wakeup()`函数启用设备唤醒功能。然后，在 PM 恢复回调中，它通过调用`enable_irq_wake()`来检查设备是否允许发出唤醒信号，然后通过`device_may_wakeup()`助手来启用唤醒事件，参数是相关的 IRQ 号。使用`device_may_wakeup()`来进行唤醒事件的启用/禁用的原因是因为用户空间可能已经更改了该设备的唤醒策略（通过`/sys/devices/.../power/wakeup` `sysfs`文件），在这种情况下，此助手将返回当前启用/禁用状态。此助手使用户空间决策与启用一致。在禁用唤醒事件的 IRQ 线之前，恢复方法也会进行相同的检查。

接下来，在驱动程序代码的底部，我们可以看到以下内容：

```
static SIMPLE_DEV_PM_OPS(imx_snvs_pwrkey_pm_ops,
                         imx_snvs_pwrkey_suspend,
                         imx_snvs_pwrkey_resume);
static struct platform_driver imx_snvs_pwrkey_driver = {
    .driver = {
        .name = “snvs_pwrkey”,
        .pm   = &imx_snvs_pwrkey_pm_ops,
        .of_match_table = imx_snvs_pwrkey_ids,
    },
    .probe = imx_snvs_pwrkey_probe,
};
```

前面显示了著名的`SIMPLE_DEV_PM_OPS`宏的用法，这意味着相同的挂起回调（即`imx_snvs_pwrkey_suspend`）将用于挂起到 RAM 或休眠睡眠状态，并且相同的恢复回调（实际上是`imx_snvs_pwrkey_resume`）将用于从这些状态恢复。设备 PM 结构被命名为`imx_snvs_pwrkey_pm_ops`，正如我们在宏中看到的那样，并且稍后提供给驱动程序。填充 PM 操作就是这么简单。

在结束本节之前，让我们注意一下此设备驱动程序中的 IRQ 处理程序：

```
static irqreturn_t imx_snvs_pwrkey_interrupt(int irq,
                                             void *dev_id)
{
    struct platform_device *pdev = dev_id;
    struct pwrkey_drv_data *pdata = platform_get_drvdata(pdev);
    pm_wakeup_event(pdata->input->dev.parent, 0);
    [...]
    return IRQ_HANDLED;
}
```

这里的关键函数是`pm_wakeup_event()`。粗略地说，它报告了一个唤醒事件。此外，这将停止当前系统状态转换。例如，在挂起路径上，它将中止挂起操作并阻止系统进入睡眠状态。以下是此函数的原型：

```
void pm_wakeup_event(struct device *dev, unsigned int msec)
```

第一个参数是唤醒源所属的设备，第二个参数`msec`是在 PM 唤醒核心自动将唤醒源切换到非活动状态之前等待的毫秒数。如果`msec`等于 0，则在报告事件后立即禁用唤醒源。如果`msec`不等于 0，则唤醒源的停用将在未来的`msec`毫秒后计划进行。

这是唤醒源的`timer`和`timer_expires`字段被使用的地方。粗略地说，唤醒事件报告包括以下步骤：

+   它增加了唤醒源的`event_count`计数器，并增加了唤醒源的`wakeup_count`，这是唤醒源可能中止挂起操作的次数。

+   如果唤醒源尚未激活（以下是激活路径上执行的步骤）：

- 它标记唤醒源为活动状态，并增加唤醒源的`active_count`元素。

- 它将唤醒源的`last_time`字段更新为当前时间。

- 如果其他字段`autosleep_enabled`为`true`，则更新唤醒源的`start_prevent_time`字段。

然后，唤醒源的停用包括以下步骤：

+   - 它将唤醒源的`active`字段设置为`false`。

+   它通过将处于活动状态的时间添加到旧值中来更新唤醒源的`total_time`字段。

+   - 如果活动状态的持续时间大于旧的`max_time`字段的值，则使用活动状态的持续时间更新唤醒源的`max_time`字段。

+   它使用当前时间更新唤醒源的`last_time`字段，删除唤醒源的计时器，并清除`timer_expires`。

+   - 如果其他字段`prevent_sleep_time`为`true`，则更新唤醒源的`prevent_sleep_time`字段。

停用可能会立即发生，如果`msec == 0`，或者如果不为零，则在将来的`msec`毫秒后进行计划。所有这些都应该提醒您`struct wakeup_source`，我们之前介绍过，其中大多数元素都是通过此函数调用更新的。 IRQ 处理程序是调用它的好地方，因为中断触发也标记了唤醒事件。您还应该注意，可以从 sysfs 接口检查任何唤醒源的每个属性，我们将在下一节中看到。

## 唤醒源和 sysfs（或 debugfs）

这里还有一些需要提及的东西，至少是为了调试目的。可以通过打印`/sys/kernel/debug/wakeup_sources`的内容列出系统中所有唤醒源的完整列表（假设`debugfs`已挂载在系统上）：

```
# cat /sys/kernel/debug/wakeup_sources
```

该文件还报告了每个唤醒源的统计信息，这些统计信息可以通过设备的与电源相关的 sysfs 属性单独收集。其中一些 sysfs 文件属性如下：

```
#ls /sys/devices/.../power/wake*
wakeup wakeup_active_count  wakeup_last_time_ms autosuspend_delay_ms wakeup_abort_count  wakeup_count	wakeup_max_time_ms wakeup_active wakeup_expire_count	wakeup_total_time_ms
```

我使用`wake*`模式来过滤与运行时 PM 相关的属性，这些属性也在同一个目录中。而不是描述每个属性是什么，更有价值的是指出在`struct wakeup_source`结构中的哪些字段中映射了前面的属性：

+   `wakeup`是一个 RW 属性，之前已经描述过。它的内容决定了`device_may_wakeup()`助手的返回值。只有这个属性是可读和可写的。这里的其他属性都是只读的。

+   `wakeup_abort_count`和`wakeup_count`是只读属性，指向相同的字段，即`wakeup->wakeup_count`。

+   `wakeup_expire_count`属性映射到`wakeup->expire_count`字段。

+   `wakeup_active`是只读的，并映射到`wakeup->active`元素。

+   `wakeup_total_time_ms`是一个只读属性，返回`wakeup->total_time`值，单位是`ms`。

+   `wakeup_max_time_ms`以`ms`返回`power.wakeup->max_time`值。

+   `wakeup_last_time_ms`是一个只读属性，对应于`wakeup->last_time`值；单位是`ms`。

+   `wakeup_prevent_sleep_time_ms`也是只读的，并映射到 wakeup `->prevent_sleep_time`值，其单位是`ms`。

并非所有设备都具有唤醒功能，但是那些具有唤醒功能的设备可以大致遵循这个指南。

现在我们已经完成并熟悉了来自 sysfs 的唤醒源管理，我们可以介绍特殊的`IRQF_NO_SUSPEND`标志，它有助于防止在系统挂起路径中禁用 IRQ。

## IRQF_NO_SUSPEND 标志

有一些中断需要能够在整个系统挂起-恢复周期中触发，包括挂起和恢复设备的`noirq`阶段，以及在非引导 CPU 被下线和重新上线时。例如，定时器中断就是这种情况。必须在这些中断上设置此标志。尽管此标志有助于在挂起阶段保持中断启用，但并不保证 IRQ 将唤醒系统从挂起状态唤醒-对于这种情况，有必要使用`enable_irq_wake()`，再次强调，这是特定于平台的。因此，您不应混淆或混合使用`IRQF_NO_SUSPEND`标志和`enable_irq_wake()`。

如果带有此标志的 IRQ 被多个用户共享，那么每个用户都会受到影响，而不仅仅是设置了该标志的用户。换句话说，即使在`suspend_device_irqs()`之后，也会像往常一样调用注册到中断的每个处理程序。这可能不是您所需要的。因此，您应该避免混合使用`IRQF_NO_SUSPEND`和`IRQF_SHARED`标志。

# 总结

在本章中，我们已经学会了如何管理系统的功耗，无论是从驱动程序中的代码内部还是从用户空间的命令行中进行操作，可以在运行时通过对单个设备进行操作，或者通过调整睡眠状态来对整个系统进行操作。我们还学会了其他框架如何帮助减少系统的功耗（如 CPUFreq、Thermal 和 CPUIdle）。

在下一章中，我们将转向处理 PCI 设备驱动程序，这些驱动程序处理着这个无需介绍的著名总线上的设备。
