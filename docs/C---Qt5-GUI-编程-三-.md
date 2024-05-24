# C++ Qt5 GUI 编程（三）

> 原文：[`annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed`](https://annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：即时通讯

企业软件的一个重要特性是与员工进行通信的能力。因此，内部即时通讯系统是软件的一个关键部分。通过在 Qt 中整合网络模块，我们可以轻松地创建一个聊天系统。

在本章中，我们将涵盖以下主题：

+   Qt 网络模块

+   创建即时通讯服务器

+   创建即时通讯客户端

使用 Qt 创建即时通讯系统比你想象的要容易得多。让我们开始吧！

# Qt 网络模块

在接下来的部分，我们将学习 Qt 的网络模块以及它如何帮助我们通过 TCP 或 UDP 连接协议实现服务器-客户端通信。

# 连接协议

Qt 的网络模块提供了低级网络功能，如 TCP 和 UDP 套接字，以及用于网络集成和网络通信的高级网络类。

在本章中，我们将使用 TCP（传输控制协议）互联网协议，而不是 UDP（用户数据报协议）协议。主要区别在于 TCP 是一种面向连接的协议，要求所有客户端在能够相互通信之前必须与服务器建立连接。

另一方面，UDP 是一种无连接的协议，不需要连接。客户端只需将需要发送到目的地的任何数据发送出去，而无需检查数据是否已被另一端接收。两种协议都有利弊，但 TCP 更适合我们的示例项目。我们希望确保每条聊天消息都被接收者接收到，不是吗？

两种协议之间的区别如下：

+   TCP：

+   面向连接的协议

+   适用于需要高可靠性的应用程序，对数据传输时间不太关键

+   TCP 的速度比 UDP 慢

+   在发送下一个数据之前，需要接收客户端的确认收据

+   绝对保证传输的数据保持完整，并按发送顺序到达目的地

+   UDP：

+   无连接协议

+   适用于需要快速、高效传输的应用程序，如游戏和 VOIP

+   UDP 比 TCP 轻量且更快，因为不会尝试错误恢复

+   也适用于需要从大量客户端回答小查询的服务器

+   没有保证发送的数据是否到达目的地，因为没有跟踪连接，也不需要接收客户端的任何确认

由于我们不打算采用点对点连接的方法，我们的聊天系统将需要两个不同的软件部分——服务器程序和客户端程序。服务器程序将充当中间人（就像邮递员一样），接收所有用户的消息并将它们发送给相应的接收者。服务器程序将被锁定在服务器房间的一台计算机中，普通用户无法接触。

另一方面，客户端程序是所有用户使用的即时通讯软件。这个程序将安装在用户的计算机上。用户可以使用这个客户端程序发送消息，并查看其他人发送的消息。我们的消息系统的整体架构看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/26bb7700-45cf-4482-9232-4eb2ce750839.png)

让我们继续设置我们的项目并启用 Qt 的网络模块！对于这个项目，我们将先从服务器程序开始，然后再处理客户端程序。

# 设置新项目

首先，创建一个新的 Qt 控制台应用程序项目。然后，打开项目文件（.pro）并添加以下模块：

```cpp
QT += core network 
Qt -= gui 
```

你应该已经注意到，这个项目没有任何`gui`模块（我们确保它被明确删除），因为服务器程序不需要任何用户界面。这也是为什么我们选择了 Qt 控制台应用程序而不是通常的 Qt 小部件应用程序的原因。

实际上，就是这样——你已经成功地将网络模块添加到了你的项目中。在下一节中，我们将学习如何为我们的聊天系统创建服务器程序。

# 创建即时通讯服务器

在接下来的部分，我们将学习如何创建一个即时通讯服务器，接收用户发送的消息并将其重新分发给各自的接收者。

# 创建 TCP 服务器

在这一部分，我们将学习如何创建一个 TCP 服务器，不断监听特定端口以接收传入的消息。为了简单起见，我们将创建一个全局聊天室，其中每个用户都可以看到聊天室内每个用户发送的消息，而不是一个一对一的消息系统带有好友列表。一旦你了解了聊天系统的运作方式，你可以很容易地将这个系统改进为后者。

首先，转到文件|新建文件或项目，并在 C++类别下选择 C++类。然后，将类命名为`server`，并选择 QObject 作为基类。在创建自定义类之前，确保选中包含 QObject 选项。你也应该注意到了`mainwindow.ui`、`mainwindow.h`和`mainwindow.cpp`的缺失。这是因为在控制台应用程序项目中没有用户界面。

一旦服务器类被创建，让我们打开`server.h`并添加以下头文件、变量和函数：

```cpp
#ifndef SERVER_H 
#define SERVER_H 

#include <QObject> 
#include <QTcpServer> 
#include <QTcpSocket> 
#include <QDebug> 
#include <QVector> 

private: 
   QTcpServer* chatServer; 
   QVector<QTcpSocket*>* allClients; 

public:
   explicit server(QObject *parent = nullptr);
 void startServer();
   void sendMessageToClients(QString message); public slots: void newClientConnection();
  void socketDisconnected();
  void socketReadyRead();
  void socketStateChanged(QAbstractSocket::SocketState state);
```

接下来，创建一个名为`startServer()`的函数，并将以下代码添加到`server.cpp`中的函数定义中：

```cpp
void server::startServer() 
{ 
   allClients = new QVector<QTcpSocket*>; 

   chatServer = new QTcpServer(); 
   chatServer->setMaxPendingConnections(10); 
   connect(chatServer, SIGNAL(newConnection()), this, 
   SLOT(newClientConnection())); 

   if (chatServer->listen(QHostAddress::Any, 8001)) 
   { 
         qDebug() << "Server has started. Listening to port 8001."; 
   } 
   else 
   { 
         qDebug() << "Server failed to start. Error: " + chatServer-
         >errorString(); 
   } 
} 
```

我们创建了一个名为`chatServer`的`QTcpServer`对象，并使其不断监听端口`8001`。你可以选择从`1024`到`49151`范围内的任何未使用的端口号。此范围之外的其他数字通常保留用于常见系统，如 HTTP 或 FTP 服务，因此最好不要使用它们以避免冲突。我们还创建了一个名为`allClients`的`QVector`数组，用于存储所有连接的客户端，以便我们以后可以利用它来将传入的消息重定向到所有用户。

我们还使用了`setMaxPendingConnections()`函数来限制最大挂起连接数为 10 个客户端。你可以使用这种方法来保持活动客户端的数量，以便服务器的带宽始终在其限制范围内。这可以确保良好的服务质量并保持积极的用户体验。

# 监听客户端

每当客户端连接到服务器时，`chatServer`将触发`newConnection()`信号，因此我们将该信号连接到我们的自定义槽函数`newClientConnection()`。槽函数如下所示：

```cpp
void server::newClientConnection() 
{ 
   QTcpSocket* client = chatServer->nextPendingConnection(); 
   QString ipAddress = client->peerAddress().toString(); 
   int port = client->peerPort(); 

   connect(client, &QTcpSocket::disconnected, this, &server::socketDisconnected); 
   connect(client, &QTcpSocket::readyRead, this, &server::socketReadyRead); 
   connect(client, &QTcpSocket::stateChanged, this, &server::socketStateChanged); 

   allClients->push_back(client); 

   qDebug() << "Socket connected from " + ipAddress + ":" + QString::number(port); 
} 
```

每个连接到服务器的新客户端都是一个`QTcpSocket`对象，可以通过调用`nextPendingConnection()`从`QTcpServer`对象中获取。你可以通过调用`peerAddress()`和`peerPort()`分别获取有关客户端的信息，如其 IP 地址和端口号。然后我们将每个新客户端存储到`allClients`数组中以供将来使用。我们还将客户端的`disconnected()`、`readyRead()`和`stateChanged()`信号连接到其相应的槽函数。

当客户端从服务器断开连接时，将触发`disconnected()`信号，随后将调用`socketDisconnected()`槽函数。在这个函数中，我们只是在服务器控制台上显示消息，当它发生时，什么都不做。你可以在这里做任何你喜欢的事情，比如将用户的离线状态保存到数据库等。为了简单起见，我们将在控制台窗口上打印出消息：

```cpp
void server::socketDisconnected() 
{ 
   QTcpSocket* client = qobject_cast<QTcpSocket*>(QObject::sender()); 
   QString socketIpAddress = client->peerAddress().toString(); 
   int port = client->peerPort(); 

   qDebug() << "Socket disconnected from " + socketIpAddress + ":" + 
   QString::number(port); 
} 
```

接下来，每当客户端向服务器发送消息时，`readyRead()`信号将被触发。我们已经将该信号连接到一个名为`socketReadyRead()`的槽函数，它看起来像这样：

```cpp
void server::socketReadyRead() 
{ 
   QTcpSocket* client = qobject_cast<QTcpSocket*>(QObject::sender()); 
   QString socketIpAddress = client->peerAddress().toString(); 
   int port = client->peerPort(); 

   QString data = QString(client->readAll()); 

   qDebug() << "Message: " + data + " (" + socketIpAddress + ":" + 
   QString::number(port) + ")"; 

   sendMessageToClients(data); 
} 
```

在上述代码中，我们只是简单地将消息重定向到一个名为`sendMessageToClients()`的自定义函数中，该函数处理将消息传递给所有连接的客户端。我们将在一分钟内看看这个函数是如何工作的。我们使用`QObject::sender()`来获取发出`readyRead`信号的对象的指针，并将其转换为`QTcpSocket`类，以便我们可以访问其`readAll()`函数。

之后，我们还将另一个名为`stateChanged()`的信号连接到`socketStateChanged()`槽函数。慢函数看起来像这样：

```cpp
void server::socketStateChanged(QAbstractSocket::SocketState state) 
{ 
   QTcpSocket* client = qobject_cast<QTcpSocket*>(QObject::sender()); 
   QString socketIpAddress = client->peerAddress().toString(); 
   int port = client->peerPort(); 

   QString desc; 

   if (state == QAbstractSocket::UnconnectedState) 
         desc = "The socket is not connected."; 
   else if (state == QAbstractSocket::HostLookupState) 
         desc = "The socket is performing a host name lookup."; 
   else if (state == QAbstractSocket::ConnectingState) 
         desc = "The socket has started establishing a connection."; 
   else if (state == QAbstractSocket::ConnectedState) 
         desc = "A connection is established."; 
   else if (state == QAbstractSocket::BoundState) 
         desc = "The socket is bound to an address and port."; 
   else if (state == QAbstractSocket::ClosingState) 
         desc = "The socket is about to close (data may still be 
         waiting to be written)."; 
   else if (state == QAbstractSocket::ListeningState) 
         desc = "For internal use only."; 

   qDebug() << "Socket state changed (" + socketIpAddress + ":" + 
   QString::number(port) + "): " + desc; 
} 
```

此函数在客户端的网络状态发生变化时触发，例如连接、断开连接、监听等。我们将根据其新状态简单地打印出相关消息，以便更轻松地调试我们的程序。

现在，让我们看看`sendMessageToClients()`函数的样子：

```cpp
void server::sendMessageToClients(QString message) 
{ 
   if (allClients->size() > 0) 
   { 
         for (int i = 0; i < allClients->size(); i++) 
         { 
               if (allClients->at(i)->isOpen() && allClients->at(i)-
               >isWritable()) 
               { 
                     allClients->at(i)->write(message.toUtf8()); 
               } 
         } 
   } 
} 
```

在上述代码中，我们只是简单地循环遍历`allClients`数组，并将消息数据传递给所有连接的客户端。

最后，打开`main.cpp`并添加以下代码来启动我们的服务器：

```cpp
#include <QCoreApplication> 
#include "server.h" 

int main(int argc, char *argv[]) 
{ 
   QCoreApplication a(argc, argv); 

   server* myServer = new server(); 
   myServer->startServer(); 

   return a.exec(); 
} 
```

现在构建并运行程序，你应该看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/07666326-5c7d-4633-8a02-641e3ae73af5.png)

除了显示服务器正在监听端口`8001`之外，似乎没有发生任何事情。别担心，因为我们还没有创建客户端程序。让我们继续！

# 创建即时通讯客户端

在接下来的部分中，我们将继续创建我们的即时通讯客户端，用户将使用它来发送和接收消息。

# 设计用户界面

在本节中，我们将学习如何为即时通讯客户端设计用户界面并为其创建功能：

1.  首先，通过转到文件|新建文件或项目来创建另一个 Qt 项目。然后在应用程序类别下选择 Qt Widget 应用程序。

1.  项目创建后，打开`mainwindow.ui`并将一个行编辑和文本浏览器拖放到窗口画布中。然后，选择中央窗口小部件并单击位于上方小部件栏上的“垂直布局”按钮，以将垂直布局效果应用到小部件上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e12c2a26-b9f7-4a29-be49-3e3e35eaa0c8.png)

1.  之后，在底部放置一个水平布局，并将行编辑放入布局中。然后，从小部件框中拖放一个按钮到水平布局中，并将其命名为`sendButton`；我们还将其标签设置为`Send`，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b6569033-78ae-4f24-8c92-52d0d24ce323.png)

1.  完成后，将另一个水平布局拖放到文本浏览器顶部。然后，将标签、行编辑和一个按钮放入水平布局中，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/65759c61-0e68-4ef7-803d-91247e04d7ae.png)

我们将行编辑小部件称为`nameInput`，并将其默认文本设置为`John Doe`，这样用户就有了默认名称。然后，我们将推按钮称为`connectButton`，并将其标签更改为`Connect`。

我们已经完成了一个非常简单的即时通讯程序的用户界面设计，它将执行以下任务：

1.  连接到服务器

1.  让用户设置他们的名字

1.  可以看到所有用户发送的消息

1.  用户可以输入并发送他们的消息供所有人查看

现在编译并运行项目，你应该看到你的程序看起来类似这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b412d5d1-4f08-44fb-bcd5-3da628cdfb2a.png)

请注意，我还将窗口标题更改为`Chat Client`，这样看起来稍微更专业一些。您可以通过在层次结构窗口中选择`MainWindow`对象并更改其`windowTitle`属性来实现。

在下一节中，我们将开始进行编程工作，并实现上面列表中提到的功能。

# 实现聊天功能

在我们开始编写任何代码之前，我们必须通过打开项目文件（`.pro`）并在那里添加 `network` 关键字来启用网络模块：

```cpp
QT += core gui network 
```

接下来，打开 `mainwindow.h` 并添加以下头文件和变量：

```cpp
#ifndef MAINWINDOW_H 
#define MAINWINDOW_H 

#include <QMainWindow> 
#include <QDebug> 
#include <QTcpSocket> 

private: 
   Ui::MainWindow *ui; 
   bool connectedToHost; 
   QTcpSocket* socket; 
```

我们在 `mainwindow.cpp` 中默认将 `connectedToHost` 变量设置为 `false`：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 
   connectedToHost = false; 
} 
```

完成此操作后，我们需要实现的第一个功能是服务器连接。打开 `mainwindow.ui`，右键单击连接按钮，然后选择转到槽...，然后选择 `clicked()`。之后，将自动为您创建一个槽函数。在 `SLOT` 函数中添加以下代码：

```cpp
void MainWindow::on_connectButton_clicked() 
{ 
   if (!connectedToHost) 
   { 
         socket = new QTcpSocket(); 

         connect(socket, SIGNAL(connected()), this, 
         SLOT(socketConnected())); 
         connect(socket, SIGNAL(disconnected()), this, 
         SLOT(socketDisconnected())); 
         connect(socket, SIGNAL(readyRead()), this, 
         SLOT(socketReadyRead())); 

         socket->connectToHost("127.0.0.1", 8001); 
   } 
   else 
   { 
         QString name = ui->nameInput->text(); 
         socket->write("<font color="Orange">" + name.toUtf8() + " has 
         left the chat room.</font>"); 

         socket->disconnectFromHost(); 
   } 
} 
```

在前面的代码中，我们基本上是检查了 `connectedToHost` 变量。如果变量为 `false`（表示客户端未连接到服务器），则创建一个名为 `socket` 的 `QTcpSocket` 对象，并使其连接到端口 `8801` 上的 `127.0.0.1` 主机。IP 地址 `127.0.0.1` 代表本地主机。由于这仅用于测试目的，我们将客户端连接到位于同一台计算机上的测试服务器。如果您在另一台计算机上运行服务器，则可以根据需要将 IP 地址更改为局域网或广域网地址。

当 `connected()`、`disconnected()` 和 `readReady()` 信号被触发时，我们还将 `socket` 对象连接到其相应的槽函数。这与我们之前所做的服务器代码完全相同。如果客户端已连接到服务器并且单击了连接（现在标记为 `Disconnect`）按钮，则向服务器发送断开连接消息并终止连接。

接下来，我们将看看槽函数，这些槽函数在上一步中连接到了 `socket` 对象。第一个是 `socketConnected()` 函数，当客户端成功连接到服务器时将被调用：

```cpp
void MainWindow::socketConnected() 
{ 
   qDebug() << "Connected to server."; 

   printMessage("<font color="Green">Connected to server.</font>"); 

   QString name = ui->nameInput->text(); 
   socket->write("<font color="Purple">" + name.toUtf8() + " has joined 
   the chat room.</font>"); 

   ui->connectButton->setText("Disconnect"); 
   connectedToHost = true; 
} 
```

首先，客户端将在应用程序输出和文本浏览器小部件上显示 `Connected to server.` 消息。我们马上就会看到 `printMessage()` 函数是什么样子。然后，我们从输入字段中获取用户的名称，并将其合并到文本消息中，然后将其发送到服务器，以便通知所有用户。最后，将连接按钮的标签设置为 `Disconnect`，并将 `connectedToHost` 变量设置为 `true`。

接下来，让我们看看 `socketDisconnected()`，正如其名称所示，每当客户端从服务器断开连接时都会被调用：

```cpp
void MainWindow::socketDisconnected() 
{ 
   qDebug() << "Disconnected from server."; 

   printMessage("<font color="Red">Disconnected from server.</font>"); 

   ui->connectButton->setText("Connect"); 
   connectedToHost = false; 
} 
```

前面的代码非常简单。它只是在应用程序输出和文本浏览器小部件上显示断开连接的消息，然后将断开按钮的标签设置为 `Connect`，将 `connectedToHost` 变量设置为 `false`。请注意，由于此函数仅在客户端从服务器断开连接后才会被调用，因此我们无法在那时向服务器发送任何消息以通知它断开连接。您应该在服务器端检查断开连接并相应地通知所有用户。

然后是 `socketReadyRead()` 函数，每当服务器向客户端发送数据时都会触发该函数。这个函数比之前的函数更简单，因为它只是将传入的数据传递给 `printMessage()` 函数，什么都不做：

```cpp
void MainWindow::socketReadyRead() 
{ 
   ui->chatDisplay->append(socket->readAll()); 
} 
```

最后，让我们看看 `printMessage()` 函数是什么样子。实际上，它就是这么简单。它只是将消息附加到文本浏览器中，然后完成：

```cpp
void MainWindow::printMessage(QString message) 
{ 
   ui->chatDisplay->append(message); 
} 
```

最后但同样重要的是，让我们看看如何实现向服务器发送消息的功能。打开 `mainwindow.ui`，右键单击发送按钮，选择转到槽...，然后选择 `clicked()` 选项。一旦为您创建了槽函数，将以下代码添加到函数中：

```cpp
void MainWindow::on_sendButton_clicked() 
{ 
   QString name = ui->nameInput->text(); 
   QString message = ui->messageInput->text(); 
   socket->write("<font color="Blue">" + name.toUtf8() + "</font>: " + 
   message.toUtf8()); 

   ui->messageInput->clear(); 
} 
```

首先，我们获取用户的名称并将其与消息组合在一起。然后，在将整个内容发送到服务器之前，我们将名称设置为蓝色，通过调用`write()`来发送。之后，清除消息输入字段，完成。由于文本浏览器默认接受富文本，我们可以使用`<font>`标签来为文本着色。

现在编译并运行项目；您应该能够在不同的客户端之间进行聊天！在连接客户端之前，不要忘记打开服务器。如果一切顺利，您应该会看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3e596014-2a86-4f29-b996-da0d30ff5cd9.png)

同时，您还应该在服务器端看到所有的活动：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/0fc60d96-fc57-4fe5-b4cd-a459653d6dcf.png)

到此为止！我们已经成功使用 Qt 创建了一个简单的聊天系统。欢迎您在此基础上进行改进，创建一个完整的消息传递系统！

# 总结

在本章中，我们学习了如何使用 Qt 的网络模块创建即时消息传递系统。在接下来的章节中，我们将深入探讨使用 Qt 进行图形渲染的奇妙之处。


# 第十一章：实现图形编辑器

Qt 为我们提供了使用`QPainter`类进行低级图形渲染的功能。Qt 能够渲染位图和矢量图像。在本章中，我们将学习如何使用 Qt 绘制形状，并最终创建我们自己的绘图程序。

在本章中，我们将涵盖以下主题：

+   绘制矢量形状

+   将矢量图像保存为 SVG 文件

+   创建绘图程序

准备好了吗？让我们开始吧！

# 绘制矢量形状

在接下来的部分，我们将学习如何在我们的 Qt 应用程序中使用 QPainter 类渲染矢量图形。

# 矢量与位图

计算机图形中有两种格式——位图和矢量。位图图像（也称为光栅图像）是以一系列称为**像素**的微小点存储的图像。每个像素将被分配一种颜色，并且以存储的方式显示在屏幕上——像素与屏幕上显示的内容之间是一一对应的关系。

另一方面，矢量图像不是基于位图模式，而是使用数学公式来表示可以组合成几何形状的线条和曲线。

这里列出了两种格式的主要特点：

+   位图：

+   通常文件大小较大

+   不能放大到更高分辨率，因为图像质量会受到影响

+   用于显示颜色丰富的复杂图像，如照片

+   矢量：

+   文件大小非常小

+   图形可以调整大小而不影响图像质量

+   每个形状只能应用有限数量的颜色（单色、渐变或图案）

+   复杂形状需要高处理能力才能生成

这里的图表比较了位图和矢量图形：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/94527953-3456-480e-92b6-2303f304d7c4.png)

在本节中，我们将专注于学习如何使用 Qt 绘制矢量图形，但我们也将在本章后面介绍位图图形。

# 使用 QPainter 绘制矢量形状

首先，通过转到文件|新建文件或项目来创建另一个 Qt 项目。然后在应用程序类别下选择 Qt Widget 应用程序。创建项目后，打开`mainwindow.h`并添加`QPainter`头文件：

```cpp
#include <QMainWindow> 
#include <QPainter> 
```

之后，我们还声明了一个名为`paintEvent()`的虚函数，这是 Qt 中的标准事件处理程序，每当需要绘制东西时都会调用它，无论是 GUI 更新、窗口调整大小，还是手动调用`update()`函数时：

```cpp
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    virtual void paintEvent(QPaintEvent *event); 
```

然后，打开`mainwindow.cpp`并添加`paintEvent()`函数：

```cpp
void MainWindow::paintEvent(QPaintEvent *event) 
{ 
   QPainter painter; 
   painter.begin(this); 

   // Draw Line 
   painter.drawLine(QPoint(50, 60), QPoint(100, 100)); 

   // Draw Rectangle 
   painter.setBrush(Qt::BDiagPattern); 
   painter.drawRect(QRect(40, 120, 80, 30)); 

   // Draw Ellipse 
   QPen ellipsePen; 
   ellipsePen.setColor(Qt::red); 
   ellipsePen.setStyle(Qt::DashDotLine); 
   painter.setPen(ellipsePen); 
   painter.drawEllipse(QPoint(80, 200), 50, 20); 

   // Draw Rectangle 
   QPainterPath rectPath; 
   rectPath.addRect(QRect(150, 20, 100, 50)); 
   painter.setPen(QPen(Qt::red, 1, Qt::DashDotLine, Qt::FlatCap, 
   Qt::MiterJoin)); 
   painter.setBrush(Qt::yellow); 
   painter.drawPath(rectPath); 

   // Draw Ellipse 
   QPainterPath ellipsePath; 
   ellipsePath.addEllipse(QPoint(200, 120), 50, 20); 
   painter.setPen(QPen(QColor(79, 106, 25), 5, Qt::SolidLine, 
   Qt::FlatCap, Qt::MiterJoin)); 
   painter.setBrush(QColor(122, 163, 39)); 
   painter.drawPath(ellipsePath); 

   painter.end(); 
} 
```

如果现在构建程序，你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/24aed423-bb6e-4adc-b33f-3804ca1972c2.png)

上面的代码真的很长。让我们把它分解一下，这样你就更容易理解了。每当调用`paintEvent()`时（通常在窗口需要绘制时会调用一次），我们调用`QPainter::begin()`告诉 Qt 我们要开始绘制东西了，然后在完成时调用`QPainter::end()`。因此，绘制图形的代码将包含在`QPainter::begin()`和`QPainter::end()`之间。

让我们看看以下步骤：

1.  我们绘制的第一件事是一条直线，这很简单——只需调用`QPainter::drawLine()`并将起点和终点值插入函数中。请注意，Qt 使用的坐标系统是以像素格式的。它的原点从应用程序窗口的左上角开始，并向右和向下方向增加，取决于*x*和*y*的值。*x*值的增加将位置移动到右方向，而*y*值的增加将位置移动到下方向。

1.  接下来，绘制一个矩形，在形状内部有一种阴影图案。这次，我们调用了`QPainter::setBrush()`来设置图案，然后调用`drawRect()`。

1.  之后，我们用虚线轮廓和图案在形状内部绘制了一个椭圆形。由于我们已经在上一步中设置了图案，所以我们不必再次设置。相反，我们使用`QPen`类在调用`drawEllipse()`之前设置轮廓样式。只需记住，在 Qt 的术语中，刷子用于定义形状的内部颜色或图案，而笔用于定义轮廓。

1.  接下来的两个形状基本上与之前的相似；我们只是改变了不同的颜色和图案，这样你就可以看到它们与之前的例子之间的区别。

# 绘制文本

此外，您还可以使用`QPainter`类来绘制文本。在调用`QPainter::drawText()`之前，您只需要调用`QPainter::setFont()`来设置字体属性，就像这样：

```cpp
QPainter painter; 
painter.begin(this); 

// Draw Text 
painter.setFont(QFont("Times", 14, QFont::Bold)); 
painter.drawText(QPoint(20, 30), "Testing"); 

// Draw Line 
painter.drawLine(QPoint(50, 60), QPoint(100, 100)) 
```

`setFont()`函数是可选的，如果您不指定它，将获得默认字体。完成后，构建并运行程序。您应该在窗口中看到“Hello World！”这个词显示出来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/69667eda-dc36-4753-be48-1c8ac3a0143f.png)

在这里你可以看到，矢量形状基本上是由 Qt 实时生成的，无论你如何重新调整窗口大小和改变它的纵横比，它看起来都很好。如果你渲染的是位图图像，当它与窗口一起重新调整大小或改变纵横比时，它的视觉质量可能会下降。

# 将矢量图像保存到 SVG 文件

除了绘制矢量图形，Qt 还允许我们将这些图形保存为矢量图像文件，称为**SVG**（可缩放矢量图形）文件格式。SVG 格式是许多软件使用的开放格式，包括 Web 浏览器用于显示矢量图形。实际上，Qt 也可以读取 SVG 文件并在屏幕上呈现它们，但我们暂时跳过这一点。让我们看看如何将我们的矢量图形保存为 SVG 文件！

这个例子继续了我们在上一节中留下的地方。因此，我们不必创建一个新的 Qt 项目，只需坚持之前的项目即可。

首先，如果主窗口还没有菜单栏，让我们为主窗口添加一个菜单栏。然后，打开`mainwindow.ui`，在表单编辑器中，右键单击层次结构窗口上的 MainWindow 对象，然后选择创建菜单栏：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6041e5ce-79df-4fd0-8b7f-0308f37da1b9.png)

完成后，将文件添加到菜单栏，然后在其下方添加“另存为 SVG”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/22dbdd71-1359-46bb-8a7e-6537dc52034e.png)

然后，转到底部的操作编辑器，右键单击我们刚刚添加的菜单选项，并选择转到槽...：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e6fe895f-60a5-4fd8-9328-d937ea068f9a.png)

将弹出一个窗口询问您选择一个信号。选择`triggered()`，然后点击确定。这样就会在`mainwindow.cpp`中为您创建一个新的槽函数。在打开`mainwindow.cpp`之前，让我们打开我们的`项目文件`（`.pro`）并添加以下`svg`模块：

```cpp
QT += core gui svg 
```

`svg`关键字告诉 Qt 向您的项目添加相关类，可以帮助您处理 SVG 文件格式。然后，我们还需要在`mainwindow.h`中添加另外两个头文件：

```cpp
#include <QtSvg/QSvgGenerator> 
#include <QFileDialog> 
```

之后，打开`mainwindow.cpp`并将以下代码添加到我们刚刚在上一步中添加的槽函数中：

```cpp
void MainWindow::on_actionSave_as_SVG_triggered() 
{ 
    QString filePath = QFileDialog::getSaveFileName(this, "Save SVG", "", "SVG files (*.svg)"); 

    if (filePath == "") 
        return; 

    QSvgGenerator generator; 
    generator.setFileName(filePath); 
    generator.setSize(QSize(this->width(), this->height())); 
    generator.setViewBox(QRect(0, 0, this->width(), this->height())); 
    generator.setTitle("SVG Example"); 
    generator.setDescription("This SVG file is generated by Qt."); 

    paintAll(&generator); 
} 
```

在前面的代码中，我们使用`QFileDialog`让用户选择他们想要保存 SVG 文件的位置。然后，我们使用`QSvgGenerator`类将图形导出到 SVG 文件中。最后，我们调用`paintAll()`函数，这是我们将在下一步中定义的自定义函数。

实际上，我们需要修改现有的`paintAll()`方法并将我们的渲染代码放入其中。然后，将`QSvgGenerator`对象作为绘制设备传递到函数输入中：

```cpp
void MainWindow::paintAll(QSvgGenerator *generator) 
{ 
    QPainter painter; 

    if (generator) 
        painter.begin(generator); 
    else 
        painter.begin(this); 

   // Draw Text 
    painter.setFont(QFont("Times", 14, QFont::Bold)); 
   painter.drawText(QPoint(20, 30), "Hello World!"); 
```

因此，我们的`paintEvent()`现在在`mainwindow.cpp`中看起来像这样：

```cpp
void MainWindow::paintEvent(QPaintEvent *event) 
{ 
   paintAll(); 
} 
```

这里的过程可能看起来有点混乱，但它的基本作用是在创建窗口时调用`paintAll()`函数一次绘制所有图形，然后当您想要将图形保存到 SVG 文件时再次调用`paintAll()`。

唯一的区别是绘图设备——一个是主窗口本身，我们将其用作绘图画布，对于后者，我们将`QSvgGenerator`对象传递为绘图设备，它将把图形保存到 SVG 文件中。

现在构建并运行程序，单击文件|保存 SVG 文件，您应该能够将图形保存到 SVG 文件中。尝试用网络浏览器打开文件，看看它是什么样子的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/982756a6-c52f-45d4-ab97-f9429e05366c.png)

看起来我的网络浏览器（Firefox）不支持填充图案，但其他东西都很好。由于矢量图形是由程序生成的，形状不存储在 SVG 文件中（只存储数学公式及其变量），您可能需要确保用户平台支持您使用的功能。

在下一节中，我们将学习如何创建我们自己的绘画程序，并使用它绘制位图图像！

# 创建绘画程序

在接下来的部分，我们将转向像素领域，并学习如何使用 Qt 创建绘画程序。用户将能够通过使用不同大小和颜色的画笔来表达他们的创造力，绘制像素图像！

# 设置用户界面

同样，对于这个例子，我们将创建一个新的 Qt Widget 应用程序。之后，打开`mainwindow.ui`并在主窗口上添加一个菜单栏。然后，在菜单栏中添加以下选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6c4c1e46-259b-4888-a009-0a1ddbbac18c.png)

我们的菜单栏上有三个菜单项——文件、画笔大小和画笔颜色。在文件菜单下有将画布保存为位图文件的功能，以及清除整个画布的功能。画笔大小类别包含不同的画笔大小选项；最后，画笔颜色类别包含设置画笔颜色的几个选项。

您可以选择更像*绘画*或*Photoshop*的 GUI 设计，但出于简单起见，我们现在将使用这个。

完成所有这些后，打开`mainwindow.h`并在顶部添加以下头文件：

```cpp
#include <QMainWindow> 
#include <QPainter> 
#include <QMouseEvent> 
#include <QFileDialog> 
```

之后，我们还声明了一些虚拟函数，如下所示：

```cpp
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    virtual void mousePressEvent(QMouseEvent *event); 
    virtual void mouseMoveEvent(QMouseEvent *event); 
    virtual void mouseReleaseEvent(QMouseEvent *event); 
    virtual void paintEvent(QPaintEvent *event); 
    virtual void resizeEvent(QResizeEvent *event); 
```

除了我们在上一个示例中使用的`paintEvent()`函数之外，我们还可以添加一些用于处理鼠标事件和窗口调整事件的函数。然后，我们还向我们的`MainWindow`类添加以下变量：

```cpp
private: 
    Ui::MainWindow *ui; 
 QImage image; 
    bool drawing; 
    QPoint lastPoint; 
    int brushSize; 
    QColor brushColor; 
```

之后，让我们打开`mainwindow.cpp`并从类构造函数开始：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
    QMainWindow(parent), 
    ui(new Ui::MainWindow) 
{ 
    ui->setupUi(this); 

 image = QImage(this->size(), QImage::Format_RGB32); 
    image.fill(Qt::white); 

    drawing = false; 
    brushColor = Qt::black; 
    brushSize = 2; 
} 
```

我们需要首先创建一个`QImage`对象，它充当画布，并将其大小设置为与我们的窗口大小相匹配。然后，我们将默认画笔颜色设置为黑色，其默认大小设置为`2`。之后，我们将看一下每个事件处理程序及其工作原理。

首先，让我们看一下`paintEvent()`函数，这也是我们在矢量图形示例中使用的。这一次，它所做的就是调用`QPainter::drawImage()`并在我们的主窗口上渲染`QImage`对象（我们的图像缓冲区）：

```cpp
void MainWindow::paintEvent(QPaintEvent *event)
{
    QPainter canvasPainter(this);
    canvasPainter.drawImage(this->rect(), image, image.rect());
}
```

接下来，我们将看一下`resizeEvent()`函数，每当用户调整主窗口大小时都会触发该函数。为了避免图像拉伸，我们必须调整图像缓冲区的大小以匹配新的窗口大小。这可以通过创建一个新的`QImage`对象并设置其大小与调整后的主窗口相同来实现，然后复制先前的 QImage 的像素信息，并将其放置在新图像缓冲区的完全相同的位置。

这意味着如果窗口大小小于绘图，您的图像将被裁剪，但至少画布不会被拉伸和扭曲图像，当窗口调整大小时。让我们看一下代码：

```cpp
void MainWindow::resizeEvent(QResizeEvent *event) 
{ 
    QImage newImage(event->size(), QImage::Format_RGB32); 
    newImage.fill(qRgb(255, 255, 255)); 

    QPainter painter(&newImage); 
    painter.drawImage(QPoint(0, 0), image); 
    image = newImage; 
} 
```

接下来，我们将看一下鼠标事件处理程序，我们将使用它来在画布上应用颜色。首先是`mousePressEvent()`函数，当我们开始按下鼠标按钮（在这种情况下是左鼠标按钮）时将触发该函数。在这一点上我们仍然没有画任何东西，但是将绘图布尔值设置为`true`并将我们的光标位置保存到`lastPoint`变量中。

```cpp
void MainWindow::mousePressEvent(QMouseEvent *event) 
{ 
    if (event->button() == Qt::LeftButton) 
    { 
        drawing = true; 
        lastPoint = event->pos(); 
    } 
} 
```

然后，这是`mouseMoveEvent()`函数，当鼠标光标移动时将被调用：

```cpp
void MainWindow::mouseMoveEvent(QMouseEvent *event) 
{ 
    if ((event->buttons() & Qt::LeftButton) && drawing) 
    { 
        QPainter painter(&image); 
        painter.setPen(QPen(brushColor, brushSize, Qt::SolidLine, 
        Qt::RoundCap, Qt::RoundJoin)); 
        painter.drawLine(lastPoint, event->pos()); 

        lastPoint = event->pos(); 
        this->update(); 
    } 
} 
```

在前面的代码中，我们检查是否确实在按住鼠标左键移动鼠标。如果是，那么我们就从上一个光标位置画一条线到当前光标位置。然后，我们保存当前光标位置到`lastPoint`变量，并调用`update()`通知 Qt 触发`paintEvent()`函数。

最后，当我们释放鼠标左键时，将调用`mouseReleaseEvent()`。我们只需将绘图变量设置为`false`，然后完成：

```cpp
void MainWindow::mouseReleaseEvent(QMouseEvent *event) 
{ 
    if (event->button() == Qt::LeftButton) 
    { 
        drawing = false; 
    } 
} 
```

如果我们现在构建并运行程序，我们应该能够在我们的小绘画程序上开始绘制一些东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/89598a8c-02fa-4d93-9868-37aa3a30d6f8.png)

尽管现在我们可以绘制一些东西，但都是相同的笔刷大小和相同的颜色。这有点无聊！让我们在主菜单的“笔刷大小”类别上右键单击每个选项，然后选择“转到槽...”，然后选择“触发()”选项，然后按“确定”。然后 Qt 将为我们创建相应的槽函数，我们需要在这些函数中做的就是基本上改变 brushSize 变量，就像这样：

```cpp
void MainWindow::on_action2px_triggered() 
{ 
    brushSize = 2; 
} 

void MainWindow::on_action5px_triggered() 
{ 
    brushSize = 5; 
} 

void MainWindow::on_action10px_triggered() 
{ 
    brushSize = 10; 
} 
```

在“笔刷颜色”类别下的所有选项也是一样的。这次，我们相应地设置了`brushColor`变量：

```cpp
void MainWindow::on_actionBlack_triggered() 
{ 
    brushColor = Qt::black; 
} 

void MainWindow::on_actionWhite_triggered() 
{ 
    brushColor = Qt::white; 
} 

void MainWindow::on_actionRed_triggered() 
{ 
    brushColor = Qt::red; 
} 

void MainWindow::on_actionGreen_triggered() 
{ 
    brushColor = Qt::green; 
} 

void MainWindow::on_actionBlue_triggered() 
{ 
    brushColor = Qt::blue; 
} 
```

如果您再次构建和运行程序，您将能够使用各种笔刷设置绘制图像：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a9b9ff12-8980-45c0-8cf2-ed3f9eaab8fe.png)

除此之外，我们还可以将现有的位图图像添加到我们的画布上，以便我们可以在其上绘制。假设我有一个企鹅图像，以 PNG 图像的形式存在（名为`tux.png`），我们可以在类构造函数中添加以下代码：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
    QMainWindow(parent), 
    ui(new Ui::MainWindow) 
{ 
    ui->setupUi(this); 

    image = QImage(this->size(), QImage::Format_RGB32); 
    image.fill(Qt::white); 

    QImage tux; 
    tux.load(qApp->applicationDirPath() + "/tux.png"); 
    QPainter painter(&image); 
    painter.drawImage(QPoint(100, 100), tux); 

    drawing = false; 
    brushColor = Qt::black; 
    brushSize = 2; 
} 
```

前面的代码基本上打开图像文件并将其移动到位置 100 x 100，然后将图像绘制到我们的图像缓冲区上。现在，每当我们启动程序时，我们就可以在画布上看到一个企鹅：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1eb1fc12-4d31-4fd6-be34-8c5c174ff48d.png)

接下来，我们将看一下“文件”下的“清除”选项。当用户在菜单栏上点击此选项时，我们使用以下代码清除整个画布（包括企鹅）并重新开始：

```cpp
void MainWindow::on_actionClear_triggered() 
{ 
    image.fill(Qt::white); 
    this->update(); 
} 
```

最后，当用户点击“文件”下的“保存”选项时，我们打开一个文件对话框，让用户将他们的作品保存为位图文件。在以下代码中，我们过滤图像格式，只允许用户保存 PNG 和 JPEG 格式：

```cpp
void MainWindow::on_actionSave_triggered() 
{ 
    QString filePath = QFileDialog::getSaveFileName(this, "Save Image", "", "PNG (*.png);;JPEG (*.jpg *.jpeg);;All files (*.*)"); 

    if (filePath == "") 
        return; 

    image.save(filePath); 
} 
```

就是这样，我们成功地使用 Qt 从头开始创建了一个简单的绘画程序！您甚至可以将从本章学到的知识与上一章结合起来，创建一个在线协作白板！唯一的限制就是您的创造力。最后，我要感谢所有读者使用我们新创建的绘画程序创建了以下杰作：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2d43a36a-906f-4b53-8e78-f4a72b9416c6.jpg)

# 总结

在这一章中，我们学习了如何绘制矢量和位图图形，随后我们使用 Qt 创建了自己的绘画程序。在接下来的章节中，我们将研究创建一个将数据传输并存储到云端的程序的方面。


# 第十二章：云存储

在上一章中，我们学习了如何使用 Qt 在屏幕上绘制图像。然而，在本章中，我们将学习完全不同的东西，即设置我们自己的文件服务器并将其链接到我们的 Qt 应用程序。

在本章中，我们将涵盖以下主题：

+   设置 FTP 服务器

+   在列表视图上显示文件列表

+   将文件上传到 FTP 服务器

+   从 FTP 服务器下载文件

让我们开始吧！

# 设置 FTP 服务器

在接下来的部分，我们将学习如何设置 FTP 服务器，该服务器存储用户上传的所有文件，并允许他们随时下载。这一部分与 Qt 无关，因此如果您已经运行了 FTP 服务器，请跳过此部分并继续本章的下一部分。

# 介绍 FTP

**FTP**是**文件传输协议**的缩写。FTP 用于在网络上从一台计算机传输文件到另一台计算机，通常是通过互联网。FTP 只是云存储技术的众多形式之一，但它也是一种简单的形式，您可以轻松地在自己的计算机上设置。

有许多不同的 FTP 服务器是由不同的人群为特定操作系统开发的。在本章的这一部分，我们将学习如何设置运行在 Windows 操作系统上的 FileZilla 服务器。如果您运行其他操作系统，如 GNU、Linux 或 macOS，还有许多其他 FTP 服务器程序可供使用，如 VSFTP 和 Pure-FTPd。

在 Debian、Ubuntu 或其他类似的 Linux 变体上，在终端上运行`sudo apt-get install vsftpd`将安装和配置 FTP 服务器。在 macOS 上，从苹果菜单中打开“系统偏好设置”，然后选择“共享”。然后，点击“服务”选项卡，选择 FTP 访问。最后，点击“启动”按钮启动 FTP 服务器。

如果您已经运行了 FTP 服务器，请跳过到下一节，我们将开始学习 C++编程。

# 下载 FileZilla

FileZilla 真的很容易设置和配置。它提供了一个完全功能的、易于使用的用户界面，不需要任何先前的操作经验。我们需要做的第一件事是下载 FileZilla。我们将按照以下步骤进行：

1.  打开浏览器，跳转到[`filezilla-project.org`](https://filezilla-project.org)。您将在主页上看到两个下载按钮。

1.  点击“下载 FileZilla 服务器”，它将带我们到下载页面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4bfbf211-e454-4edf-bc21-d4658021c8eb.png)

1.  一旦您到达下载页面，点击“下载 FileZilla 服务器”按钮并开始下载软件。我们不会使用 FileZilla 客户端，所以您不需要下载它。一切准备就绪后，让我们继续安装软件。

1.  像大多数 Windows 软件一样，安装过程非常简单。保持一切默认，然后一直点击下一步，直到安装过程开始。安装过程最多只需要几分钟。

1.  完成后，点击“关闭”按钮，我们完成了！：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1f2e50ce-e947-4859-9cb8-7b4325f307d9.png)

# 设置 FileZilla

安装完 FileZilla 后，控制面板很可能会自动打开。

1.  由于这是您第一次启动 FileZilla，它将要求您设置服务器。将服务器 IP 地址保持为`127.0.0.1`（即**localhost**），将管理员端口设置为`14147`。

1.  输入您想要的服务器管理密码，并勾选“始终连接到此服务器”选项。点击连接，FTP 服务器现在将启动！如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6c47f55c-7b14-4f7e-bb5f-43c5af4b817c.png)

1.  FTP 服务器启动后，我们需要创建一个用户帐户。点击左侧的第四个图标打开“用户”对话框：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/90d51fc3-b15a-43fd-afc2-b99511c8b1f6.png)

1.  然后，在常规页面下，单击窗口右侧的添加按钮。通过设置用户名创建一个帐户，然后单击确定。

1.  我们现在不必为用户设置任何组，因为用户组仅在您有许多具有相同特权设置的用户时才有用，因为这样可以更容易地一次更改所有用户的设置或将用户移动到不同的组中。创建用户后，选中密码选项并输入所需的密码。将密码放在您的 FTP 帐户上始终是一个好习惯：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/93277ddc-baa0-4121-a281-25dcef5ebd9e.png)

1.  之后，我们将继续到共享文件夹页面，并为我们新创建的用户添加一个共享目录。

1.  确保删除和追加选项已选中，以便可以替换具有相同名称的文件。我们将在稍后使用它来更新我们的文件列表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/51573cbf-7f90-4144-8677-cba2ec6bad13.png)

1.  如果单击从左起的第三个图标，将出现 FileZilla 服务器选项对话框。您基本上可以在这里配置一切以满足您的需求。例如，如果您不想使用默认端口号`21`，您可以在选项窗口中简单地更改它，在常规设置页面下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/697d6dcd-114e-4477-bc2e-7437b0905d2a.png)

1.  您还可以在速度限制页面为所有用户或特定用户设置速度限制。这可以防止您的服务器在许多用户同时下载大文件时性能下降：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1868a1d7-c12b-482b-9536-b844f2e7d50c.png)

接下来，让我们继续创建我们的 Qt 项目！

# 在列表视图上显示文件列表

在上一节中，我们成功地设置了一个 FTP 服务器并使其保持运行。在接下来的部分中，我们将学习如何创建一个 FTP 客户端程序，该程序显示文件列表，将文件上传到 FTP 服务器，最后从中下载文件。

# 设置项目

像往常一样，让我们使用**Qt Creator**创建一个新项目。以下步骤将有所帮助：

1.  我们可以通过转到文件|新文件或项目并选择 Qt 小部件应用程序来创建一个新项目。

1.  创建项目后，打开您的项目（`.pro`）文件，并添加`network`关键字，以便 Qt 知道您的项目需要网络模块：

```cpp
QT += core gui network
```

# 设置用户界面

之后，打开`mainwindow.ui`并执行以下步骤来设计用户界面的上半部分以上传文件：

1.  放置一个标签，上面写着上传文件：放在其他小部件的顶部。

1.  在标签下方放置一个水平布局和两个按钮，分别写着打开和上传。

1.  在水平布局下放置一个进度条。

1.  在底部放置一个水平线，然后是垂直间隔器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8a026044-0639-4540-af80-4de768b78ffa.jpg)

接下来，我们将构建用户界面的底部部分，用于下载文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3130468f-e520-4536-8be3-2b8c472857ee.jpg)

这次，我们的用户界面与上半部分非常相似，只是我们在第二个进度条之前添加了一个列表视图来显示文件列表。我们将所有内容放在同一页上，以便更简单和不易混淆地解释这个示例程序。

# 显示文件列表

接下来，我们将学习如何保存并显示 FTP 服务器上的文件列表。实际上，FTP 服务器默认提供文件列表，并且 Qt 能够在旧版本中使用`qtftp`模块显示它。但是，自从版本 5 以来，Qt 已经完全放弃了`qtftp`模块，这个功能不再存在。

如果您仍然对旧的`qtftp`模块感兴趣，您仍然可以通过访问以下链接在 GitHub 上获取其源代码：[`github.com/qt/qtftp`](https://github.com/qt/qtftp)

在 Qt 中，我们使用`QNetworkAccessManager`类与我们的 FTP 服务器通信，因此不再使用专门为 FTP 设计的功能。但是，不用担心，我们将研究一些其他替代方法来实现相同的结果。

在我看来，最好的方法是使用在线数据库来存储文件列表及其信息（文件大小、格式、状态等）。如果您有兴趣学习如何将 Qt 应用程序连接到数据库，请参阅第三章，*数据库连接*。然而，为了简单起见，我们将使用另一种方法，它可以正常工作，但不够安全——直接将文件名保存在文本文件中，并将其存储在 FTP 服务器上。

如果您正在为客户或公司做一个严肃的项目，请不要使用这种方法。查看第三章，*数据库连接*，并学习使用实际数据库。

好吧，假设除了使用文本文件之外没有其他办法；我们该怎么做呢？很简单：创建一个名为`files.txt`的文本文件，并将其放入我们在本章开头创建的 FTP 目录中。

# 编写代码

接下来，打开`mainwindow.h`并添加以下头文件：

```cpp
#include <QMainWindow> 
#include <QDebug> 
#include <QNetworkAccessManager> 
#include <QNetworkRequest> 
#include <QNetworkReply> 
#include <QFile> 
#include <QFileInfo> 
#include <QFileDialog> 
#include <QListWidgetItem> 
#include <QMessageBox> 
```

之后，添加以下变量和函数：

```cpp
private: 
   Ui::MainWindow *ui; 
 QNetworkAccessManager* manager; 

   QString ftpAddress; 
   int ftpPort; 
   QString username; 
   QString password; 

   QNetworkReply* downloadFileListReply; 
   QNetworkReply* uploadFileListReply; 

   QNetworkReply* uploadFileReply; 
   QNetworkReply* downloadFileReply; 

   QStringList fileList; 
   QString uploadFileName; 
   QString downloadFileName; 

public:
   void getFileList();
```

完成上一步后，打开`mainwindow.cpp`并将以下代码添加到类构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

 manager = new QNetworkAccessManager(this); 

   ftpAddress = "ftp://127.0.0.1/"; 
   ftpPort = 21; 
   username = "tester"; // Put your FTP user name here
   password = "123456"; // Put your FTP user password here 
   getFileList(); 
} 
```

我们所做的基本上是初始化`QNetworkAccessManager`对象并设置存储我们的 FTP 服务器信息的变量，因为我们将在后续步骤中多次使用它。之后，我们将调用`getFileList()`函数开始从 FTP 服务器下载`files.txt`。`getFileList()`函数如下所示：

```cpp
void MainWindow::getFileList() 
{ 
   QUrl ftpPath; 
   ftpPath.setUrl(ftpAddress + "files.txt"); 
   ftpPath.setUserName(username); 
   ftpPath.setPassword(password); 
   ftpPath.setPort(ftpPort); 

   QNetworkRequest request; 
   request.setUrl(ftpPath); 

   downloadFileListReply = manager->get(request); 
   connect(downloadFileListReply, &QNetworkReply::finished, this, 
   &MainWindow::downloadFileListFinished); 
} 
```

我们使用`QUrl`对象来存储有关我们的服务器和我们试图下载的文件位置的信息，然后将其提供给`QNetworkRequest`对象，然后通过调用`QNetworkAccessManager::get()`将其发送出去。由于我们不知道何时所有文件将完全下载，因此我们利用了 Qt 的`SIGNAL`和`SLOT`机制。

我们连接了来自`downloadFileListReply`指针（指向`mainwindow.h`中的`QNetworkReply`对象）的`finished()`信号，并将其链接到`slot`函数`downloadFileListFinished()`，如下所示：

```cpp
void MainWindow::downloadFileListFinished() 
{ 
   if(downloadFileListReply->error() != QNetworkReply::NoError) 
   { 
         QMessageBox::warning(this, "Failed", "Failed to load file 
         list: " + downloadFileListReply->errorString()); 
   } 
   else 
   { 
         QByteArray responseData; 
         if (downloadFileListReply->isReadable()) 
         { 
               responseData = downloadFileListReply->readAll(); 
         } 

         // Display file list 
         ui->fileList->clear(); 
         fileList = QString(responseData).split(","); 

         if (fileList.size() > 0) 
         { 
               for (int i = 0; i < fileList.size(); i++) 
               { 
                     if (fileList.at(i) != "") 
                     { 
                           ui->fileList->addItem(fileList.at(i)); 
                     } 
               } 
         } 
   } 
} 
```

代码有点长，所以我将函数分解为以下步骤：

1.  如果在下载过程中出现任何问题，请显示一个消息框，告诉我们问题的性质。

1.  如果一切顺利并且下载已经完成，我们将尝试通过调用`downloadFileListReply` | `readAll()`来读取数据。

1.  然后，清空列表窗口并开始解析文本文件的内容。我们在这里使用的格式非常简单；我们只使用逗号符号来分隔每个文件名：`filename1,filename2,filename,...`。重要的是我们不要在实际项目中这样做。

1.  一旦我们调用`split(",")`将字符串拆分为字符串列表，就进行`for`循环并在列表窗口中显示每个文件名。

测试前面的代码是否有效，创建一个名为`files.txt`的文本文件，并将以下文本添加到文件中：

```cpp
filename1,filename2,filename3 
```

然后，将文本文件放到 FTP 目录中并运行项目。您应该能够在应用程序中看到它出现如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/515e1c2d-015e-4fd2-88e6-9588304c21a9.png)

一旦它工作正常，我们可以清空文本文件的内容并继续下一节。

# 将文件上传到 FTP 服务器

由于我们的 FTP 目录中还没有任何文件（除了文件列表），让我们编写代码以允许我们上传我们的第一个文件。

1.  首先，打开`mainwindow.ui`，右键单击“打开”按钮。然后，选择“转到槽”并选择“clicked()”选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9101a98a-64cd-4902-b2ea-d463509b03d9.png)

1.  将自动为您创建一个`slot`函数。然后，将以下代码添加到函数中，以打开文件选择器窗口，让用户选择要上传的文件：

```cpp
void MainWindow::on_openButton_clicked() 
{ 
   QString fileName = QFileDialog::getOpenFileName(this, "Select 
   File", qApp->applicationDirPath()); 
   ui->uploadFileInput->setText(fileName); 
}
```

1.  之后，重复此步骤，并对“上传”按钮执行相同操作。这次，其`slot`函数的代码看起来像下面这样：

```cpp
void MainWindow::on_uploadButton_clicked() 
{ 
   QFile* file = new QFile(ui->uploadFileInput->text()); 
   QFileInfo fileInfo(*file); 
   uploadFileName = fileInfo.fileName(); 

   QUrl ftpPath; 
   ftpPath.setUrl(ftpAddress + uploadFileName); 
   ftpPath.setUserName(username); 
   ftpPath.setPassword(password); 
   ftpPath.setPort(ftpPort); 

   if (file->open(QIODevice::ReadOnly)) 
   { 
         ui->uploadProgress->setEnabled(true); 
         ui->uploadProgress->setValue(0); 

         QNetworkRequest request; 
         request.setUrl(ftpPath); 

         uploadFileReply = manager->put(request, file); 
         connect(uploadFileReply, 
         SIGNAL(uploadProgress(qint64,qint64)), this, 
         SLOT(uploadFileProgress(qint64,qint64))); 
         connect(uploadFileReply, SIGNAL(finished()), this,  
         SLOT(uploadFileFinished())); 
   } 
   else 
   { 
         QMessageBox::warning(this, "Invalid File", "Failed to open 
         file for upload."); 
   } 
} 

```

代码看起来有点长，所以让我们分解一下：

1.  我们使用`QFile`类打开我们要上传的文件（文件路径取自`ui->uploadFileInput->text()`）。如果文件不存在，显示一个消息框通知用户。

1.  然后，我们将 FTP 服务器和上传目的地的信息填入一个`QUrl`对象中，然后将其提供给`QNetworkRequest`对象。

1.  之后，我们开始读取文件的内容，并将其提供给`QNetworkAccessManager::put()`函数。

1.  由于我们不知道文件何时会完全上传，我们使用了 Qt 提供的`SIGNAL`和`SLOT`机制。我们将`uploadProgress()`和`finished()`信号链接到我们的两个自定义`slot`函数`uploadFileProgress()`和`uploadFileFinised()`。

`slot`函数`uploadFileProgress()`将告诉我们上传的当前进度，因此我们可以用它来设置进度条：

```cpp
void MainWindow::uploadFileProgress(qint64 bytesSent, qint64 bytesTotal) 
{ 
   qint64 percentage = 100 * bytesSent / bytesTotal; 
   ui->uploadProgress->setValue((int) percentage); 
} 
```

与此同时，当文件完全上传时，`uploadFileFinished()`函数将被触发：

```cpp
void MainWindow::uploadFileFinished() 
{ 
   if(uploadFileReply->error() != QNetworkReply::NoError) 
   { 
         QMessageBox::warning(this, "Failed", "Failed to upload file: " 
         + uploadFileReply->errorString()); 
   } 
   else 
   { 
         QMessageBox::information(this, "Success", "File successfully 
         uploaded."); 
   } 
} 

```

我们还没有完成前面的函数。由于已向 FTP 服务器添加了新文件，我们必须更新现有文件列表，并替换存储在 FTP 目录中的`files.txt`文件。由于代码稍微长一些，我们将把代码分成几个部分，这些部分都发生在显示文件成功上传消息框之前。

1.  首先，让我们检查新上传的文件是否已经存在于我们的文件列表中（替换 FTP 服务器上的旧文件）。如果存在，我们可以跳过整个过程；否则，将文件名追加到我们的`fileList`字符串列表中，如下所示：

```cpp
// Add new file to file list array if not exist yet 
bool exists = false; 
if (fileList.size() > 0) 
{ 
   for (int i = 0; i < fileList.size(); i++) 
   { 
         if (fileList.at(i) == uploadFileName) 
         { 
               exists = true; 
         } 
   } 
} 

if (!exists) 
{ 
   fileList.append(uploadFileName); 
} 
```

1.  之后，在我们应用程序的目录中创建一个临时文本文件（`files.txt`），并将新文件列表保存在文本文件中：

```cpp
// Create new files.txt 
QString fileName = "files.txt"; 
QFile* file = new QFile(qApp->applicationDirPath() + "/" + fileName); 
file->open(QIODevice::ReadWrite); 
if (fileList.size() > 0) 
{ 
   for (int j = 0; j < fileList.size(); j++) 
   { 
         if (fileList.at(j) != "") 
         { 
               file->write(QString(fileList.at(j) + ",").toUtf8()); 
         } 
   } 
} 
file->close(); 
```

1.  最后，我们使用`QFile`类打开我们刚创建的文本文件，并将其再次上传到 FTP 服务器以替换旧的文件列表：

```cpp
// Re-open the file 
QFile* newFile = new QFile(qApp->applicationDirPath() + "/" + fileName); 
if (newFile->open(QIODevice::ReadOnly)) 
{ 
   // Update file list to server 
   QUrl ftpPath; 
   ftpPath.setUrl(ftpAddress + fileName); 
   ftpPath.setUserName(username); 
   ftpPath.setPassword(password); 
   ftpPath.setPort(ftpPort); 

   QNetworkRequest request; 
   request.setUrl(ftpPath); 
   uploadFileListReply = manager->put(request, newFile); 
   connect(uploadFileListReply, SIGNAL(finished()), this, SLOT(uploadFileListFinished())); 
   file->close(); 
} 
```

1.  再次使用`SIGNAL`和`SLOT`机制，以便在文件列表上传完成时得到通知。`slot`函数`uploadFileListFinished()`看起来像下面这样：

```cpp
void MainWindow::uploadFileListFinished() 
{ 
   if(uploadFileListReply->error() != QNetworkReply::NoError) 
   { 
         QMessageBox::warning(this, "Failed", "Failed to update file list: " + uploadFileListReply->errorString()); 
   } 
   else 
   { 
         getFileList(); 
   } 
} 

```

1.  我们基本上只是在更新文件列表到 FTP 服务器后再次调用`getFileList()`。如果现在构建和运行项目，您应该能够将第一个文件上传到本地 FTP 服务器，万岁！

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9f62c8f3-6cf9-42aa-8a69-8d79ea69d13b.png)

# 从 FTP 服务器下载文件

现在我们已经成功将第一个文件上传到 FTP 服务器，让我们创建一个功能，将文件下载回我们的计算机！

1.  首先，再次打开`mainwindow.ui`，右键单击“设置文件夹”按钮。选择转到槽... 并选择 clicked()信号以创建一个`slot`函数。`slot`函数非常简单；它只会打开一个文件选择对话框，但这次它只允许用户选择一个文件夹，因为我们为其提供了一个`QFileDialog::ShowDirsOnly`标志：

```cpp
void MainWindow::on_setFolderButton_clicked() 
{ 
   QString folder = QFileDialog::getExistingDirectory(this, tr("Open Directory"), qApp->applicationDirPath(), QFileDialog::ShowDirsOnly); 
   ui->downloadPath->setText(folder); 
} 
```

1.  然后，在列表窗口上右键单击并选择转到槽... 这一次，我们将选择`itemDoubleClicked(QListWidgetItem*)`选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ccd5fed6-24d3-4345-a7b5-06be7331f314.png)

1.  当用户在列表窗口中双击项目时，将触发以下函数，启动下载。文件名可以通过调用`item->text()`从`QListWidgetItem`对象中获取：

```cpp
void MainWindow::on_fileList_itemDoubleClicked(QListWidgetItem *item) 
{ 
   downloadFileName = item->text(); 

   // Check folder 
   QString folder = ui->downloadPath->text(); 
   if (folder != "" && QDir(folder).exists()) 
   { 
         QUrl ftpPath; 
         ftpPath.setUrl(ftpAddress + downloadFileName); 
         ftpPath.setUserName(username); 
         ftpPath.setPassword(password); 
         ftpPath.setPort(ftpPort); 

         QNetworkRequest request; 
         request.setUrl(ftpPath); 

         downloadFileReply = manager->get(request); 
         connect(downloadFileReply, 
         SIGNAL(downloadProgress(qint64,qint64)), this, 
         SLOT(downloadFileProgress(qint64,qint64))); 
         connect(downloadFileReply, SIGNAL(finished()), this, 
         SLOT(downloadFileFinished())); 
   } 
   else 
   { 
         QMessageBox::warning(this, "Invalid Path", "Please set the 
         download path before download."); 
   } 
} 
```

1.  就像我们在`upload`函数中所做的那样，我们在这里也使用了`SIGNAL`和`SLOT`机制来获取下载过程的进展以及完成信号。`slot`函数`downloadFileProgress()`将在下载过程中被调用，我们用它来设置第二个进度条的值：

```cpp
void MainWindow::downloadFileProgress(qint64 byteReceived,qint64 bytesTotal) 
{ 
   qint64 percentage = 100 * byteReceived / bytesTotal; 
   ui->downloadProgress->setValue((int) percentage); 
} 
```

1.  然后，当文件完全下载时，`slot`函数`downloadFileFinished()`将被调用。之后，我们将读取文件的所有数据并将其保存到我们想要的目录中：

```cpp
void MainWindow::downloadFileFinished() 
{ 
   if(downloadFileReply->error() != QNetworkReply::NoError) 
   { 
         QMessageBox::warning(this, "Failed", "Failed to download 
         file: " + downloadFileReply->errorString()); 
   } 
   else 
   { 
         QByteArray responseData; 
         if (downloadFileReply->isReadable()) 
         { 
               responseData = downloadFileReply->readAll(); 
         } 

         if (!responseData.isEmpty()) 
         { 
               // Download finished 
               QString folder = ui->downloadPath->text(); 
               QFile file(folder + "/" + downloadFileName); 
               file.open(QIODevice::WriteOnly); 
               file.write((responseData)); 
               file.close(); 

               QMessageBox::information(this, "Success", "File 
               successfully downloaded."); 
         } 
   } 
}
```

1.  现在构建程序，你应该能够下载文件列表上列出的任何文件！

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9b76d2da-fc18-4ff7-9e3f-1a559ee1d2cf.png)

# 总结

在本章中，我们学习了如何使用 Qt 的网络模块创建自己的云存储客户端。在接下来的章节中，我们将学习更多关于多媒体模块，并使用 Qt 从头开始创建自己的多媒体播放器。


# 第十三章：多媒体查看器

在上一章中，我们学习了如何通过云存储上传和下载文件。现在，在本章中，我们将学习如何使用 Qt 的多媒体模块打开这些文件，特别是媒体文件，如图像、音乐和视频。

在本章中，我们将涵盖以下主题：

+   重新访问多媒体模块

+   图像查看器

+   音乐播放器

+   视频播放器

让我们开始！

# 重新访问多媒体模块

在本章中，我们将再次使用多媒体模块，这在第九章中已经介绍过，*相机模块*。但是，这一次我们将使用模块的其他部分，所以我认为剖析模块并看看里面有什么是个好主意。

# 剖析模块

多媒体模块是一个非常庞大的模块，包含许多不同的部分，提供非常不同的功能和功能。主要类别如下：

+   音频

+   视频

+   相机

+   收音机

请注意，处理图像格式的类，如`QImage`、`QPixmap`等，不是多媒体模块的一部分，而是 GUI 模块的一部分。这是因为它们是 GUI 的重要组成部分，不能分开。尽管如此，我们仍将在本章中介绍`QImage`类。

在每个类别下都有一些子类别，看起来像下面这样：

+   音频：

+   音频输出

+   音频录制器

+   视频：

+   视频录制器

+   视频播放器

+   视频播放列表

+   相机：

+   相机取景器

+   相机图像捕获

+   相机视频录制器

+   收音机：

+   收音机调谐器（适用于支持模拟收音机的设备）

每个类都设计用于实现不同的目的。例如，`QSoundEffect`用于播放低延迟音频文件（如 WAV 文件）。另一方面，`QAudioOutput`将原始音频数据输出到特定的音频设备，这使您可以对音频输出进行低级控制。最后，`QMediaPlayer`是一个高级音频（和视频）播放器，支持许多不同的高延迟音频格式。在选择项目的正确类之前，您必须了解所有类之间的区别。

Qt 中的多媒体模块是一个庞大的怪兽，经常会让新手感到困惑，但如果您知道该选择哪个，它可能会带来好处。多媒体模块的另一个问题是，它可能会或可能不会在您的目标平台上工作。这是因为在所有这些类的底层都有特定平台的本机实现。如果特定平台不支持某个功能，或者尚未对其进行实现，那么您将无法使用这些功能。

有关 Qt 多媒体模块提供的不同类的更多信息，请访问以下链接：

[`doc.qt.io/qt-5.10/qtmultimedia-index.html`](https://doc.qt.io/qt-5.10/qtmultimedia-index.html)

# 图像查看器

数字图像已经成为我们日常生活中的重要组成部分。无论是自拍、毕业晚会照片还是有趣的表情包，我们花费大量时间查看数字图像。在接下来的部分中，我们将学习如何使用 Qt 和 C++创建我们自己的图像查看器。

# 为图像查看器设计用户界面

让我们开始创建我们的第一个多媒体程序。在本节中，我们将创建一个图像查看器，正如其名称所示，它会打开一个图像文件并在窗口上显示它：

1.  让我们打开 Qt Creator 并创建一个新的 Qt Widgets 应用程序项目。

1.  之后，打开`mainwindow.ui`并向中央窗口添加一个`Label`（命名为`imageDisplay`），它将用作渲染图像的画布。然后，通过选择中央窗口并按下位于画布顶部的垂直布局按钮，向 centralWidget 添加一个布局：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/5e2e8370-e62f-4fe3-a04e-3b95358c4be8.png)

1.  您可以删除工具栏和状态栏以给`Label`腾出空间。此外，将中央窗口的布局边距设置为`0`：

1.  之后，双击菜单栏，添加一个文件操作，然后在其下方添加打开文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8cb08727-5a95-4356-8c66-787f8a8a9aeb.png)

1.  然后，在操作编辑器下，右键单击打开文件操作，选择转到槽...：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b5e3338b-a8c9-4402-af8c-a5f030de6057.png)

1.  将弹出一个窗口，询问您选择一个信号，因此选择`triggered()`，然后点击确定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c9f8f7e1-2970-42cf-adf4-726ef91fae7b.png)

一个`slot`函数将自动为您创建，但我们将在下一部分保留它。我们已经完成了用户界面，而且真的很简单。接下来，让我们继续并开始编写我们的代码！

# 为图像查看器编写 C++代码

让我们通过以下步骤开始：

1.  首先，打开`mainwindow.h`并添加以下头文件：

```cpp
#include <QMainWindow> 
#include <QFileDialog> 
#include <QPixmap> 
#include <QPainter>
```

1.  然后，添加以下变量，称为`imageBuffer`，它将作为指向重新缩放之前的实际图像数据的指针。然后，也添加函数：

```cpp
private: 
   Ui::MainWindow *ui; 
 QPixmap* imageBuffer; 

public:
   void resizeImage();
 void paintEvent(QPaintEvent *event);

public slots:
   void on_actionOpen_triggered();
```

1.  接下来，打开`mainwindow.cpp`并在类构造函数中初始化`imageBuffer`变量：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 
   imageBuffer = nullptr; 
} 
```

1.  之后，在上一部分中 Qt 为我们创建的`slot`函数中添加以下代码：

```cpp
void MainWindow::on_actionOpen_triggered() 
{ 
   QString fileName = QFileDialog::getOpenFileName(this, "Open Image File", qApp->applicationDirPath(), "JPG (*.jpg *.jpeg);;PNG (*.png)"); 

   if (!fileName.isEmpty()) 
   { 
         imageBuffer = new QPixmap(fileName); 
         resizeImage(); 
   } 
}
```

1.  上述代码基本上打开了文件选择对话框，并创建了一个`QPixmap`对象，其中包含所选的图像文件。完成所有这些后，它将调用`resizeImage()`函数，代码如下所示：

```cpp
void MainWindow::resizeImage() 
{ 
   if (imageBuffer != nullptr) 
   { 
         QSize size = ui->imageDisplay->size(); 
         QPixmap pixmap = imageBuffer->scaled(size, 
            Qt::KeepAspectRatio); 

         // Adjust the position of the image to the center 
         QRect rect = ui->imageDisplay->rect(); 
         rect.setX((this->size().width() - pixmap.width()) / 2); 
         rect.setY((this->size().height() - pixmap.height()) / 2); 

         QPainter painter; 
         painter.begin(this); 
         painter.drawPixmap(rect, pixmap, ui->imageDisplay->rect()); 
         painter.end(); 
   } 
} 
```

`resizeImage()`函数的作用是简单地从`imageBuffer`变量中复制图像数据，并将图像调整大小以适应窗口大小，然后显示在窗口的画布上。您可能打开的图像比屏幕分辨率大得多，我们不希望在打开这样一个大图像文件时裁剪图像。

我们使用`imageBuffer`变量的原因是，这样我们可以保留原始数据的副本，并且不会通过多次调整大小来影响图像质量。

最后，我们还在`paintEvent()`函数中调用`resizeImage()`函数。每当主窗口被调整大小或从最小化状态恢复时，`paintEvent()`将自动被调用，`resizeImage()`函数也将被调用，如下所示：

```cpp
void MainWindow::paintEvent(QPaintEvent *event) 
{ 
   resizeImage(); 
} 
```

就是这样。如果现在构建并运行项目，您应该会得到一个看起来像下面这样的漂亮的图像查看器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fca8f4b0-48cb-4037-ba35-3518c6beac66.png)

# 音乐播放器

在接下来的部分中，我们将学习如何使用 Qt 和 C++构建自定义音乐播放器。

# 为音乐播放器设计用户界面

让我们继续下一个项目。在这个项目中，我们将使用 Qt 构建一个音频播放器。执行以下步骤：

1.  与上一个项目一样，我们将创建一个`Qt Widgets 应用程序`项目。

1.  打开`项目文件(.pro)`，并添加`multimedia`模块：

```cpp
QT += core gui multimedia 
```

1.  我们添加了`multimedia`文本，以便 Qt 在我们的项目中包含与多媒体模块相关的类。接下来，打开`mainwindow.ui`，并参考以下截图构建用户界面：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e87dedd9-939f-4e7d-a19f-3bb2bad50497.png)

我们基本上在顶部添加了一个标签，然后添加了一个水平滑块和另一个标签来显示音频的当前时间。之后，我们在底部添加了三个按钮，分别是播放按钮、暂停按钮和停止按钮。这些按钮的右侧是另一个水平布局，用于控制音频音量。

如您所见，所有按钮目前都没有图标，很难分辨每个按钮的用途。

1.  要为按钮添加图标，让我们转到文件 | 新建文件或项目，并在 Qt 类别下选择 Qt 资源文件。然后，创建一个名为`icons`的前缀，并将图标图像添加到前缀中：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d2370cbd-83c0-45ae-99b9-47fd81a252d7.png)

1.  之后，通过设置其图标属性并选择选择资源...，将这些图标添加到推按钮。然后，将位于音量滑块旁边的标签的`pixmap`属性设置为音量图标：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ab91665f-5ce4-4f6b-b1f4-9b2772ab7fa2.png)

1.  在您将图标添加到推按钮和标签之后，用户界面应该看起来更好了！![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cd321651-a9b0-45bb-8e91-72c15d5d11b3.png)

我们已经完成了用户界面，让我们继续进行编程部分！

# 为音乐播放器编写 C++代码

要为音乐播放器编写 C++代码，请执行以下步骤：

1.  首先，打开`mainwindow.h`并添加以下标头：

```cpp
#include <QMainWindow> 
#include <QDebug> 
#include <QFileDialog> 
#include <QMediaPlayer> 
#include <QMediaMetaData> 
#include <QTime> 
```

1.  之后，添加`player`变量，它是一个`QMediaPlayer`指针。然后，声明我们将稍后定义的函数：

```cpp
private: 
   Ui::MainWindow *ui; 
   QMediaPlayer* player; 

public:
 void stateChanged(QMediaPlayer::State state);
 void positionChanged(qint64 position);
```

1.  接下来，打开`mainwindow.cpp`并初始化播放器变量：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   player = new QMediaPlayer(this); 
   player->setVolume(ui->volume->value()); 
   connect(player, &QMediaPlayer::stateChanged, this, &MainWindow::stateChanged); 
   connect(player, &QMediaPlayer::positionChanged, this, &MainWindow::positionChanged); 
} 
```

`QMediaPlayer`类是我们的应用程序用来播放由其加载的任何音频文件的主要类。因此，我们需要知道音频播放的状态及其当前位置。我们可以通过将其`stateChanged()`和`positionChanged()`信号连接到我们的自定义`slot`函数来获取这些信息。

1.  `stateChanged()`信号允许我们获取有关音频播放的当前状态的信息。然后，我们相应地启用和禁用推按钮：

```cpp
void MainWindow::stateChanged(QMediaPlayer::State state) 
{ 
   if (state == QMediaPlayer::PlayingState) 
   { 
         ui->playButton->setEnabled(false); 
         ui->pauseButton->setEnabled(true); 
         ui->stopButton->setEnabled(true); 
   } 
   else if (state == QMediaPlayer::PausedState) 
   { 
         ui->playButton->setEnabled(true); 
         ui->pauseButton->setEnabled(false); 
         ui->stopButton->setEnabled(true); 
   } 
   else if (state == QMediaPlayer::StoppedState) 
   { 
         ui->playButton->setEnabled(true); 
         ui->pauseButton->setEnabled(false); 
         ui->stopButton->setEnabled(false); 
   } 
} 

```

1.  至于`positionChanged()`和`slot`函数，我们使用它们来设置时间轴滑块以及计时器显示：

```cpp
 void MainWindow::positionChanged(qint64 position) 
{ 
   if (ui->progressbar->maximum() != player->duration()) 
         ui->progressbar->setMaximum(player->duration()); 

   ui->progressbar->setValue(position); 

   int seconds = (position/1000) % 60; 
   int minutes = (position/60000) % 60; 
   int hours = (position/3600000) % 24; 
   QTime time(hours, minutes,seconds); 
   ui->durationDisplay->setText(time.toString()); 
} 

```

1.  完成后，打开`mainwindow.ui`，右键单击每个推按钮，然后选择转到槽...然后选择`clicked()`信号。这将为每个推按钮生成一个`slot`函数。这些`slot`函数的代码非常简单：

```cpp
void MainWindow::on_playButton_clicked() 
{  
   player->play(); 
} 

void MainWindow::on_pauseButton_clicked() 
{ 
   player->pause(); 
} 

void MainWindow::on_stopButton_clicked() 
{ 
   player->stop(); 
} 
```

1.  之后，在两个水平滑块上右键单击，并选择转到槽...然后选择`sliderMoved()`信号，然后单击确定：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e66e337a-4d88-42fb-a93e-7499babbe61d.png)

1.  每当用户拖动滑块更改其位置时，都会调用`sliderMoved()`信号。我们需要将此位置发送到媒体播放器，并告诉它调整音频音量或更改当前音频位置。请注意不要将音量滑块的默认位置设置为零。考虑以下代码：

```cpp
void MainWindow::on_volume_sliderMoved(int position) 
{ 
   player->setVolume(position); 
} 

void MainWindow::on_progressbar_sliderMoved(int position) 
{ 
   player->setPosition(position); 
} 
```

1.  然后，我们需要向菜单栏添加文件和打开文件操作，就像我们在上一个示例项目中所做的那样。

1.  然后，在操作编辑器中右键单击打开文件操作，选择转到槽...之后，选择`triggered()`，让 Qt 为您生成一个`slot`函数。将以下代码添加到用于选择音频文件的`slot`函数中：

```cpp
 void MainWindow::on_actionOpen_File_triggered() 
{ 
   QString fileName = QFileDialog::getOpenFileName(this,
      "Select Audio File", qApp->applicationDirPath(), 
       "MP3 (*.mp3);;WAV (*.wav)"); 
   QFileInfo fileInfo(fileName); 

   player->setMedia(QUrl::fromLocalFile(fileName)); 

   if (player->isMetaDataAvailable()) 
   { 
         QString albumTitle = player-
         >metaData(QMediaMetaData::AlbumTitle).toString(); 
         ui->songNameDisplay->setText("Playing " + albumTitle); 
   } 
   else 
   { 
         ui->songNameDisplay->setText("Playing " + 
           fileInfo.fileName()); 
   } 

   ui->playButton->setEnabled(true); 
   ui->playButton->click(); 
} 

```

上述简单地打开一个文件选择对话框，只接受 MP3 和 WAV 文件。如果您愿意，也可以添加其他格式，但支持的格式因平台而异；因此，您应该测试以确保您想要使用的格式受支持。

之后，它将选定的音频文件发送到媒体播放器进行预加载。然后，我们尝试从元数据中获取音乐的标题，并在`Labelwidget`上显示它。但是，此功能（获取元数据）可能会或可能不会受到您的平台支持，因此，以防它不会显示，我们将其替换为音频文件名。最后，我们启用播放按钮并自动开始播放音乐。

就是这样。如果您现在构建并运行项目，您应该能够获得一个简单但完全功能的音乐播放器！

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7da6ec50-1bc9-4ef7-8120-2c9b755c11fd.png)

# 视频播放器

在上一节中，我们已经学习了如何创建音频播放器。在本章中，我们将进一步改进我们的程序，并使用 Qt 和 C++创建视频播放器。

# 为视频播放器设计用户界面

下一个示例是视频播放器。由于`QMediaPlayer`还支持视频输出，我们可以使用上一个音频播放器示例中的相同用户界面和 C++代码，只需对其进行一些小的更改。

1.  首先，打开`项目文件（.pro）`并添加另一个关键字，称为`multimediawidgets`：

```cpp
QT += core gui multimedia multimediawidgets 
```

1.  然后，打开`mainwindow.ui`，在时间轴滑块上方添加一个水平布局（将其命名为`movieLayout`）。之后，右键单击布局，选择转换为 | QFrame。然后将其 sizePolicy 属性设置为 Expanding, Expanding：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c0c92ef1-df28-4145-86a6-361aae7a70db.png)

1.  之后，我们通过设置其`styleSheet`属性将 QFrame 的背景设置为黑色：

```cpp
background-color: rgb(0, 0, 0); 
```

1.  用户界面应该看起来像下面这样，然后我们就完成了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/eebc0672-a33c-47c9-98f3-237b4dc4e74c.png)

# 为视频播放器编写 C++代码

要为视频播放器编写 C++代码，我们执行以下步骤：

1.  对于`mainwindow.h`，对它的更改并不多。我们只需要在头文件中包含`QVideoWidget`：

```cpp
#include <QMainWindow> 
#include <QDebug> 
#include <QFileDialog> 
#include <QMediaPlayer> 
#include <QMediaMetaData> 
#include <QTime> 
#include <QVideoWidget> 
```

1.  然后，打开`mainwindow.cpp`。在将其添加到我们在上一步中添加的`QFrame`对象的布局之前，我们必须定义一个`QVideoWidget`对象并将其设置为视频输出目标：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   player = new QMediaPlayer(this); 

   QVideoWidget* videoWidget = new QVideoWidget(this); 
   player->setVideoOutput(videoWidget); 
   ui->movieLayout->addWidget(videoWidget); 

   player->setVolume(ui->volume->value()); 
   connect(player, &QMediaPlayer::stateChanged, this, &MainWindow::stateChanged); 
   connect(player, &QMediaPlayer::positionChanged, this, &MainWindow::positionChanged); 
} 
```

1.  在`slot`函数中，当“打开文件”操作被触发时，我们只需将文件选择对话框更改为仅接受`MP4`和`MOV`格式。如果您愿意，也可以添加其他视频格式：

```cpp
QString fileName = QFileDialog::getOpenFileName(this, "Select Movie File", qApp->applicationDirPath(), "MP4 (*.mp4);;MOV (*.mov)"); 
```

就是这样。代码的其余部分与音频播放器示例几乎相同。这个示例的主要区别在于我们定义了视频输出小部件，Qt 会为我们处理其余部分。

如果我们现在构建和运行项目，应该会得到一个非常流畅的视频播放器，就像您在这里看到的那样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/45c1d750-a1a7-4261-8ce5-c7821acb069e.png)

在 Windows 系统上，有一个情况是视频播放器会抛出错误。这个问题类似于这里报告的问题：[`stackoverflow.com/questions/32436138/video-play-returns-directshowplayerservicedoseturlsource-unresolved-error-cod`](https://stackoverflow.com/questions/32436138/video-play-returns-directshowplayerservicedoseturlsource-unresolved-error-cod)

要解决此错误，只需下载并安装 K-Lite_Codec_Pack，您可以在此处找到：[`www.codecguide.com/download_k-lite_codec_pack_basic.htm`](https://www.codecguide.com/download_k-lite_codec_pack_basic.htm)。之后，视频应该可以正常播放！

# 总结

在本章中，我们已经学会了如何使用 Qt 创建自己的多媒体播放器。接下来的内容与我们通常的主题有些不同。在接下来的章节中，我们将学习如何使用 QtQuick 和 QML 创建触摸友好、移动友好和图形导向的应用程序。
