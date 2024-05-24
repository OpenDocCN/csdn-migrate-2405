# 安卓 SQLite 基础知识（二）

> 原文：[`zh.annas-archive.org/md5/C362B2CF2341EAB7AC3F3FDAF20E2012`](https://zh.annas-archive.org/md5/C362B2CF2341EAB7AC3F3FDAF20E2012)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：小心操作

|   | *"过早优化是万恶之源。"* |   |
| --- | --- | --- |
|   | --*-Donald Knuth* |

在上一章中，我们涵盖了一个非常重要的概念：内容提供程序。我们以一步一步的方式进行了进展，详细介绍了如何创建内容提供程序以及如何使用现有系统与内容提供程序。我们还介绍了如何通过创建一个测试应用程序来访问我们创建的内容提供程序。

在本章中，我们将探讨如何使用加载器，特别是一种名为游标加载器的加载器。我们将通过一个示例来了解如何异步与内容提供程序进行交互。我们将讨论安卓数据库中的重要安全主题，以及如何确保数据在安卓模型中得到保护。最后但并非最不重要的是，我们还将看到一些代码片段，涵盖了如何升级数据库以及如何在应用程序中预装数据库。

在本章中，我们将涵盖以下主题：

+   使用 CursorLoader 加载数据

+   数据安全

+   一般提示和库

# 使用 CursorLoader 加载数据

`CursorLoader`是加载器家族的一部分。在我们深入探讨如何使用`CursorLoader`的示例之前，我们将稍微探讨一下加载器以及为什么它在当前情况下很重要。

## 加载器

在 HoneyComb（API 级别 11）中引入，**加载器**的作用是在活动或片段中异步提供数据。需要加载器的原因有很多：在主 UI 线程上调用各种耗时方法以获取数据导致界面笨重，甚至在某些情况下出现可怕的 ANR 对话框。这在以下截图中有所展示：

![加载器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_01.jpg)

例如，`managedQuery()`方法在 API 11 中已被弃用，它是`ContentResolver'squery()`方法的包装器。

在上一章中，我们在强调如何在查询方法中从内容提供程序中获取数据时，使用了`getContentResolver.query()`而不是`managedQuery()`。使用弃用的方法可能会导致未来版本出现问题，应该避免使用。

加载器为活动或片段在非 UI 线程上异步加载数据。加载器或加载器的子类在单独的线程中执行其工作，并将结果传递到主线程。在单独的线程中工作时，从主线程中调用和在主线程上发布结果的分离确保我们拥有一个响应迅速的应用程序。

### 提示

在加载器时代之后，我们面临着诸如当活动由于配置更改而需要重新创建时的问题，例如，设备方向的旋转。我们必须在创建新实例时担心数据和重新获取数据。但是有了加载器，我们不必担心所有这些，因为加载器在设备配置更改后重新创建时会自动重新连接到上一个加载器的游标并重新获取数据。作为额外的奖励，加载器监视数据源，并在内容更改时提供新的结果。换句话说，加载器会自动更新，因此无需重新查询游标。在安卓开发者网站上阅读更多关于保持您的安卓应用程序响应迅速并避免**应用程序无响应**（**ANR**）消息的内容，网址为[`developer.android.com/training/articles/perf-anr.html`](http://developer.android.com/training/articles/perf-anr.html)。

## 加载器 API 摘要

让我们来看看由各种类和接口组成的加载器 API。在本节中，我们将看一下加载器 API 类/接口的实现方面：

| 类/接口 | 描述 |
| --- | --- |
| `LoaderManager` | 这是与活动或片段关联的抽象类，用于管理加载器。虽然可以有一个或多个加载器实例，但每个活动或片段只允许一个`LoaderManager`实例。它负责处理活动或片段的生命周期，特别是在运行长时间任务时非常有帮助。 |
| `LoaderManager.LoaderCallbacks` | 这是一个回调接口，我们必须实现以与`LoaderManager`交互。 |
| `Loader` | 这是加载器的基类。它是一个执行数据异步加载的抽象类。我们可以实现自己的子类，而不是使用诸如`CursorLoader`之类的子类。 |
| `AsyncTaskLoader` | 这是一个抽象的加载器，提供`AsyncTask`在后台执行工作，也就是在单独的线程上；然而，结果是在主线程上传递的。根据文档，建议子类化`AsyncTaskLoader`而不是直接子类化`Loader`类。 |
| `CursorLoader` | 这是`AsyncTaskLoader`的子类，它在后台线程上以非阻塞方式查询`ContentResolver`并返回游标。 |

## 使用 CursorLoader

加载器为我们提供了许多方便的功能；其中之一是一旦我们的活动或片段实现了加载器，就不需要担心刷新数据。加载器为我们监视数据源，反映任何更改，甚至执行新的加载；所有这些都是异步完成的。因此，我们不需要关心实现和管理线程，将查询卸载到后台线程，并在查询完成后检索结果。

加载器可以处于以下三种不同状态之一：

+   **启动状态**：一旦启动，加载器将保持在此状态，直到停止或重置。它执行加载，监视任何更改，并将其反映给监听器。

+   **停止状态**：在这里，加载器继续监视更改，但不将结果传递给客户端。

+   **重置状态**：在此状态下，加载器释放其持有的任何资源，并不执行执行、加载或监视数据的过程。

现在，我们将重新查看我们的个人联系人管理应用程序，并对我们的应用程序实现`CursorLoader`进行相应的更改。`CursorLoader`，顾名思义，是一个查询`ContentResolver`并返回游标的加载器。这是`AsyncTaskLoader`的子类，并在后台线程上执行游标查询，以便不阻塞应用程序的 UI。在图表中，您可以看到加载器回调的各种方法以及它们如何与`CursorLoader`和`CursorAdapter`进行通信。

![使用 CursorLoader](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_07.jpg)

要实现游标加载器，我们需要执行以下步骤：

1.  首先，我们需要实现`LoaderManager.LoaderCallbacks<Cursor>`接口：

```kt
public class ContactsMainActivity extends Activity implements OnClickListener, LoaderManager.LoaderCallbacks<Cursor> {…}
```

然后，实现反映加载器不同状态的方法：`onCreateLoader()`，`onLoadFinished()`和`onLoaderReset()`。

1.  发起查询，我们将调用`LoaderManager.initLoader()`方法；这将初始化后台框架。

```kt
getLoaderManager().initLoader(CUR_LOADER, null, this);
```

`CUR_LOADER`值传递给`onCreateLoader()`方法，它充当加载器的 ID。对`initloader()`的调用会调用`onCreateLoader()`，传递我们用于调用`initloader()`的 ID：

```kt
@Override
public Loader<Cursor> onCreateLoader(int loaderID, 
Bundle bundle)
{
  switch (loaderID) {
  case CUR_LOADER:
    return new CursorLoader(this, PersonalContactContract.CONTENT_URI,
      PersonalContactContract.PROJECTION_ALL, null, null, null );
    default: return null;
   }
}
```

1.  我们使用 switch case 根据其 ID 获取加载器，并对于无效的 ID 返回`null`。我们创建一个 URI 对象`contentUri`并将其作为参数传递给`CursorLoader`构造函数。需要注意的是，我们可以使用此构造函数或空的未指定的游标加载器`CursorLoader(Context context)`来实现游标加载器。此外，我们可以通过方法设置值，例如`setUri(Uri)`，`setSelection(String)`，`setSelectionArgs(String[])`，`setSortOrder(String)`和`setProjection(String[])`：

```kt
public CursorLoader (Context context, Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)
```

以下是上述代码的参数：

+   `context`：这是父活动的上下文。

+   `uri`：我们使用`contentURI`，采用`content://`方案，来检索内容。它可以基于 ID 或目录。

+   `projection`：这是要返回的列的列表，因为我们已经准备好了列名。传递`null`将返回所有列。

+   `selection`：这被格式化为 SQL 的`WHERE`子句，不包括`WHERE`本身，作为一个过滤器声明要返回哪些行。

+   `selectionArgs`：我们可以在选择中包含问号，这些问号将被`selectionArgs`中绑定的字符串值替换，并按照它们的选择顺序出现。

+   `sortOrder`：这告诉我们如何对行进行排序，格式为 SQL 的`ORDER BY`子句。空值将使用默认排序顺序。

1.  `onCreateLoader`在后台启动查询，当查询完成时，游标加载器对象被传递给后台的框架，框架调用`onLoadFinished()`，我们在这里提供游标对象数据给我们的适配器实例：

```kt
@Override
public void onLoadFinished(Loader<Cursor> loader, Cursor data)
{
  this.mAdapter.changeCursor(data);
}
```

1.  适配器是`CursorAdapter`的子类。我们不再使用传统的通过扩展`BaseAdapter`获得的`getView()`方法，而是使用`bindView()`和`newView()`方法。我们在`newView`中填充我们的列表视图行布局，而在 bind view 中，我们执行类似于`getView()`方法的操作。我们定义我们的布局元素，并将其与相关数据关联起来：

```kt
public class CustomCursorAdapter extends CursorAdapter
{
   ...
  public void bindView(View view, Context arg1, Cursor cursor)
  {
    finalImageView contact_photo = (ImageView) view
      .findViewById(R.id.contact_photo);
  ...
  ...
  contact_email.setText(cursor.getString(cursor
       .getColumnIndexOrThrow(DatabaseConstants.TABLE_ROW_EMAIL)));
  setImage(cursor.getBlob(cursor
       .getColumnIndex(DatabaseConstants.TABLE_ROW_PHOTOID)),
      contact_photo);
   }

   @Override
  public View newView(Context arg0, Cursor arg1, ViewGroup arg2)
  {
    final View view = LayoutInflater.from(context).inflate(
      R.layout.contact_list_row, null, false);
    return view;
   }
...
}
```

1.  当游标加载器被重置时，将调用此方法。我们通过向`changeCursor()`方法传递`null`来清除对游标的任何引用。每当与游标相关的数据发生更改时，游标加载器在重新运行查询之前调用此方法，以清除任何过去的引用，从而防止内存泄漏。一旦设置了`onLoaderReset()`，游标加载器将重新运行其查询。

```kt
@Override
public void onLoaderReset(Loader<Cursor> loader) 
{
  this.mAdapter.changeCursor(null);

    }
```

1.  现在我们转向我们的内容提供程序，在那里我们必须进行一些小的更改，以确保我们对数据库所做的任何更改都反映在我们应用程序的列表视图中：

```kt
cr.setNotificationUri(getContext().getContentResolver(),uri);
```

1.  我们需要在`ContentProvider`的查询方法中通过游标在`ContentResolver`中注册`observer`。我们这样做是为了监视内容 URI 的任何更改，这可以是特定数据行或表的 URI：

```kt
getContext().getContentResolver().notifyChange(ur,null);
```

1.  在`insert()`方法中，我们使用`notifyChange()`方法通知已注册的观察者行已更新。默认情况下，`CursorAdapter`对象将收到此通知。因此，现在当我们通过在我们的应用程序中插入新联系人来添加新的数据行时，将通过调用`contentProvider`的`insert()`方法：

```kt
resolver.insert(PersonalContactContract.CONTENT_URI, prepareData(contact));
```

1.  对于`delete()`和`update()`方法，需要执行类似的操作，这两种方法都留给读者作为练习，因为大部分样板代码都已经存在。实现加载器是简单的，可以节省我们很多线程方面的麻烦，强烈建议在执行此任务时避免令人不悦的 UI。

### 注意

`loadInBackground()`是另一个重要的方法；这返回一个用于加载操作的游标实例，并在工作线程上调用。理想情况下，`loadInBackground()`不应直接返回加载操作的结果，但我们可以通过重写`deliverResult(D)`方法来实现这一点。要取消，我们需要检查`isLoadInBackgroundCanceled()`的值，就像在`AsyncTask`中检查`isCancelled()`一样，定期检查。

# 数据安全

安全是当今的热门词。Android 生态系统确保我们的数据库不会暴露给窥探的眼睛；然而，一个 rooted 设备可能会暴露我们的数据库，就像我们在第二章*连接点*中看到的那样。借助 rooted 设备，模拟器和`adb pull`命令，在我们的情况下，我们拉取了我们的数据库以便使用 SQLite 管理工具进行检查。另一个重要的方面是内容提供程序；在设置权限时，我们需要小心。我们应该强制执行适当权限的申请过程，以便告知用户应用程序对数据的控制，使用`contract`类。

## ContentProvider 和权限

在第三章*分享是关心*中，我们简要介绍了*将提供者添加到清单*部分中的权限主题。让我们再详细介绍一下：

1.  如前所述，在将内容提供程序添加到清单时，我们还将添加我们的自定义权限。这将确保两件事，即阻止应用程序中的未经授权的操作，并告知用户权限：

```kt
<provider
android:name="com.personalcontactmanager.provider.PersonalContactProvider"
android:authorities="com.personalcontactmanager.provider"
android:readPermission="com.personalcontactmanager.provider.read"
android:exported="true"
android:grantUriPermissions="true"
>
```

1.  此外，我们将在清单中添加`permissions`标签，以指示其他应用程序将需要的权限集：

```kt
<permission
android:name="com.personalcontactmanager.provider.read"
android:icon="@drawable/ic_launcher"
android:label="Contact Manager"
android:protectionLevel="normal" >
</permission>  
```

1.  现在，在我们想要访问内容提供程序的应用程序中，我们使用`permission`标签，在我们的情况下，在代码包中使用`Ch4-TestApp`：

```kt
<uses-permission android:name="com.personalcontactmanager.provider.read" />
```

当用户安装此应用程序时，他们将收到我们的自定义权限消息以及应用程序所需的其他权限。在这一步中，不要直接从 Eclipse 运行应用程序，而是导出一个 apk 并安装它：

![ContentProvider 和权限](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_02.jpg)

如果您没有在应用程序中定义权限，并且应用程序尝试访问内容提供程序，它将收到`SecurityException: Permission Denial`消息。

如果我们创建的内容提供程序不打算共享，我们需要将`android:exported="true"`属性更改为`false`。这将使我们的内容提供程序更安全，如果有人试图对其运行恶意查询，他们将遇到安全异常。

如果我们只想在我们的应用程序之间共享数据，Android 提供了一个解决方案；我们可以使用`android:protectionLevel`并将权限设置为`signature`而不是`normal`。为此，实现内容提供程序和想要访问它的应用程序都必须在导出时由相同的密钥签名。这是因为奖励签名权限不需要用户确认。这不会让用户感到困惑，因为它是在内部完成的，也不会影响用户体验。

## 加密关键数据

我们已经讨论了其他应用程序对我们的数据库有什么样的访问权限，以及如何有效地共享我们的内容提供程序，我们也简要讨论了为什么我们不应该相信系统是绝对安全的。在最安全的方法中，敏感数据不会保存在设备上，而是保存在服务器上，并且它将使用令牌来授予访问权限。如果必须将数据存储在设备的数据库中，请使用加密。使用用户定义的密钥来加密和解密敏感数据。

我们将探讨一种使用加密数据库的方法，如果有人能够通过 root 或利用备份的手段提取它，那么它将是不可读的。如果有人试图使用 SQLite Manager 或其他工具来读取它，他们将收到友好的消息，就像下面截图中显示的那样；这是我们将用一个名为 SQLCipher 的库在一会儿创建的数据库文件。

![加密关键数据](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_03.jpg)

SQLCipher 是 SQLite 的一个开源扩展，提供了数据库文件的透明 256 位 AES 加密，正如他们的网站上所提到的。部署 SQLCipher 非常容易。现在我们将看一下构建一个示例应用程序的步骤：

1.  首先，我们将从[`sqlcipher.net/open-source`](http://sqlcipher.net/open-source)下载所需的文件。在这里，他们列出了基于 Android 的 SQLCipher 的社区版；下载它。

1.  现在我们将在我们的 eclipse 环境中创建一个新的 Android 项目。

1.  在下载的文件夹中，我们会找到`libs`文件夹；里面是一组我们需要与 SQLCipher 一起使用的 jar 文件。我们还会注意到文件夹被命名为`armeabi`，`armeabi-v7a`和`x86`，所有这些文件夹都包含`.so`文件。如果您熟悉 Android NDK，这不会是新鲜事。`.so`文件是共享对象文件，是动态库的组成部分。对于不同的架构，我们需要不同的`.so`文件，因此有三个文件夹。如果您正在运行 x86 模拟器，则需要在`libs`文件夹中使用`x86`文件夹。为简单起见，我们将所有文件夹复制到`libs`文件夹中。将`asset`文件夹的内容复制到我们项目的`asset`文件夹中，并导航到项目的属性。它看起来像以下截图。您还可以在项目的类路径中看到这些 JAR 文件。此项目的初始设置现在已经完成。![加密关键数据](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_04.jpg)

完成必要的设置后，让我们开始编写代码来制作一个小型测试应用程序：

```kt
public class MainActivity extends Activity
{
  TextView showResult;

   @Override
   protected void onCreate(Bundle savedInstanceState)
   {  
super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main);
  showResult = (TextView) findViewById(R.id.showResult);
  InitializeSQLCipher();
   }

   private void InitializeSQLCipher()
   {
SQLiteDatabase.loadLibs(this);
  File databaseFile = getDatabasePath("test.db");
  databaseFile.mkdirs();
  databaseFile.delete();
  SQLiteDatabase database = SQLiteDatabase
      .openOrCreateDatabase(databaseFile, "test123", null);
  database.execSQL("create table t1(a, b)");
  database.execSQL("insert into t1(a, b) values(?, ?)",
        new Object[] {"I am ", "Encrypted" });
   }

   public void runQuery(View v)
   {
  File databaseFile = getDatabasePath("test.db");
  SQLiteDatabase database = SQLiteDatabase.openOrCreateDatabase(
      databaseFile, "test123", null);
  String selection = "select * from t1";
  Cursor c = database.rawQuery(selection, null);
  c.moveToFirst();
  showResult.setText(c.getString(c.getColumnIndex("a")) + 
c.getString(c.getColumnIndex("b")));
    }
}
```

上述代码有两个主要方法：`InitializeSQLCipher()`和`runQuery()`。在`InitializeSQLCipher()`中，我们通过调用`loadLibs()`方法加载我们的`.so`库文件。

1.  现在我们找到数据库的绝对路径，并创建缺少的父文件夹。通过`openOrCreateDatabase()`，我们将调用打开现有数据库或者如果数据库不存在则创建一个。我们将执行标准的数据库调用来创建一个具有列`a`和`b`的表，并在一行中插入值。

现在我们将执行一个简单的查询，将值取回到`runQuery()`方法。您会注意到，除了加载库之外，我们使用的所有核心方法基本上都是标准的，那么主要的变化在哪里呢？转到代码包中的`Ch4-PersonalContactManager`示例，注意我们使用的包：

```kt
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
```

我们有 SQLCipher 包：

```kt
import net.sqlcipher.Cursor;
import net.sqlcipher.database.SQLiteDatabase;
```

实现简单，熟悉且易于实现。如果您将数据库取出并尝试读取它，您将会发现错误消息，就像我们之前在截图中显示的那样。用户将不会发现任何变化，甚至我们应用程序的逻辑仍然保持不变。在截图中，您可以看到我们刚刚构建的应用程序屏幕，它加密了数据库：

![加密关键数据](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_05.jpg)

### 注意

**OAuth**是授权的开放标准。它为客户端应用程序提供了*安全的委托访问*，以代表资源所有者访问服务器资源。它规定了资源所有者授权第三方访问其服务器资源而不共享其凭据的过程，如维基百科所述；在[`oauth.net/2/`](http://oauth.net/2/)了解更多关于 OAuth 的信息。

# 一般提示和库

我们将涵盖一些一般和不那么一般的解决方法和实践，这取决于情况。例如，在某些情况下，我们需要拥有一个预填充的值数据库，我们将在我们的 Android 应用程序中使用，或者升级一个数据库，这似乎微不足道，但可能会破坏我们的应用程序。

## 升级数据库

在第二章中，*连接点*，我们使用`onUpgrade()`来展示数据库如何更新。如果我们回到这个例子，您会注意到它执行了`Drop Table`命令。这里将发生的是原始表将被删除，并且通过`onCreate()`调用将创建一个新表。这将导致现有数据的丢失，因此不适合我们需要修改数据库的情况。`onUpgrade()`函数可以定义如下：

```kt
public void onUpgrade(SQLiteDatabase db, int oldVersion,int newVersion)
{
  String DROP_TABLE = "DROP TABLE IF EXISTS " + TABLE_NAME;
  db.execSQL(DROP_TABLE);
  onCreate(db);
}
```

另一个挑战是确定我们在这里使用的版本。用户可能正在运行应用程序的旧版本，因此我们必须记住应用程序具有的不同版本以及这些版本是否会对数据库带来任何更改。对于新用户，我们不需要担心，因为如果数据库不存在，将调用`onCreate()`。

为了确保我们有一个适当的升级，我们将在我们的`CustomSQLiteOpenHelper`类中使用`DB_VERSION`常量，告诉我们的`onUpgrade()`方法要采取的操作：

```kt
private static final int DB_VERSION = 1;
```

我们将把`DB_VERSION`常量更改为`3`以反映升级：

```kt
private static final int DB_VERSION = 3;
```

构造函数会处理其余的事情：

```kt

public CustomSQLiteOpenHelper(Context context) 
{
  super(context, DB_NAME, null, DB_VERSION);
}  
```

当运行超类构造函数时，它会将存储的 SQLite`.db`文件的`DB_VERSION`常量与我们作为参数传递的`DB_VERSION`进行比较，并在需要时调用`onUpgrade()`方法：

```kt
public void onUpgrade(SQLiteDatabase db, int oldVersion,int newVersion)
{
switch(oldVersion) {
   case 1: db.execSQL(DATABASE_CREATE_MAIN_TABLE);
   case 2: db.execSQL(DATABASE_CREATE_MAIN_TABLE);
   case 3: db.execSQL(DATABASE_CREATE_DEL_TABLE);
   }
}
```

在我们的`onUpgrade()`方法中，我们有一个 switch case 来进行更改。请注意，我们不使用`break`语句，因为用户可能使用旧版本，并且可能没有更新应用程序，如前面所述。例如，假设用户正在运行`DB_VERSION =1`的应用程序的特定版本，并且跳过了包含`DB_VERSION =2`的下一个更新，最终发布了一个具有`DB_VERSION =3`的新版本的应用程序。现在，我们有一个情况，用户仍在使用旧版本的应用程序，并且尚未安装我们发布的新更新。因此，在这种情况下，当用户安装应用程序时，`onUpgrade()`方法将首先执行`case 1`，然后转到`case 2`以安装用户错过的更新；最后，用户将安装第三个版本的更新，确保所有数据库更改都得到反映。请注意，这里没有`break`语句。这是因为我们希望运行`switch`语句获得值`1`的所有情况以及`switch`语句获得值`2`的最后两个语句。

或者，我们也可以使用`if`语句。这也会按照我们的意图进行，因为我们的测试`DB_VERSION`常量是`1`，这将满足两个条件并反映出更改：

```kt
if (oldVersion<2) {db.execSQL(DATABASE_CREATE_MORE_TABLE); } 
if (oldVersion<3) {db.execSQL(DATABASE_CREATE_DEL_TABLE); }
```

## 无需 SQL 语句的数据库

在本书的大部分内容中，我们寻找了 Android 和 SQLite 的各个角落。对于一些人来说，编写 SQL 语句可能只是在办公室的另一天，而对于一些人来说，这可能是一次过山车之旅。本节将介绍一个库，它使我们能够在不编写任何 SQL 语句的情况下保存和检索 SQLite 数据库记录。**ActiveAndroid**是用于 Android 的活动记录风格的 SQLite 持久化。根据文档，每个数据库记录都被整洁地包装到一个具有`save()`和`delete()`等方法的类中。我们将使用 ActiveAndroid 文档中的示例，并基于此构建一个可工作的示例。让我们看看启动和运行所需的步骤。

查看官方网站[`www.activeandroid.com/`](http://www.activeandroid.com/)，了解概述并从[`goo.gl/oW2kod`](http://goo.gl/oW2kod)下载文件。

下载文件后，在根文件夹上运行`ant`来构建 JAR 文件。运行`ant`后，您将在`dist`文件夹中找到您的 JAR 文件。在 Eclipse 中，创建一个新项目，将 JAR 文件添加到项目的`libs`文件夹中，然后将 JAR 文件添加到项目属性中的**Java Build Path**中。

ActiveAndroid 会查找通过执行以下步骤配置的一些全局设置：

1.  我们将首先创建一个类，扩展应用程序类：

```kt
public class MyApplication extends com.activeandroid.app.Application 
{
   @Override
public void onCreate()
{
     super.onCreate();
     ActiveAndroid.initialize(this);
    }

   @Override
public void onTerminate()
{
     super.onTerminate();
     ActiveAndroid.dispose();
   }

}
```

1.  现在我们将把这个应用程序类添加到我们的清单文件中，并添加与我们的应用程序对应的元数据：

```kt
<application
  android:name="com.active.android.MyApplication">
  <meta-data
     android:name="AA_DB_NAME"
     android:value="test.db" />
  <meta-data
     android:name="AA_DB_VERSION"
     android:value="1" />
………..
</application>
```

1.  完成了这个基本设置后，我们现在将继续创建我们的数据模型。ActiveAndroid 库支持注释，我们将在以下模型类中使用它：

```kt
// Category class

@Table(name = "Categories")
public class Category extends Model
{
@Column(name = "Name")
public String name;
}

// Item class

@Table(name = "Items")
public class Item extends Model 
{
   // If name is omitted, then the field name is used.
@Column(name = "Name")
public String name;

@Column(name = "Category")
public Category category;

public Item() 
{
     super();
   }

   public Item(String name, Category category)
   {
     super();
     this.name = name;
     this.category = category;   
   }
   }
```

### 注意

如果您想探索注释并在项目中使用它们并减少样板代码，您可以查看以下 Android 库：Android Annotations，Square's Dagger 和 ButterKnife。

1.  要添加新的类别或项目，我们需要调用`save()`。在代码段中，我们可以看到创建了一个项目对象并与特定类别关联，并且最后调用了`save()`：

```kt
public void insert(View v) 
{
  Item testItem = new Item();
  testItem.category = testCategory;
  testItem.name = editTextItem.getText().toString();
  testItem.save();
}
```

要删除项目，我们可以调用`item.delete()`。同样，要获取值，我们也有相关的方法。以下是调用特定类别的所有数据的调用：

```kt
  List<Item>getall = new Select().from(Item.class)
       .where("Category = ?", testCategory.getId())
       .orderBy("Name ASC").execute();
```

在 ActiveAndroid 中还有很多可以探索的内容。他们有模式迁移和类型序列化；除此之外，您还可以通过将数据库放在`asset`文件夹中来提供预填充数据库，并且还可以使用内容提供程序。简而言之，这是一个为寻求间接与数据库通信并执行数据库操作的人构建的良好库。它有助于以熟悉的 Java 方法形式访问数据库，而不是准备 SQL 语句来执行相同的操作。完整的示例代码捆绑在`第四章`的代码包中。

## 使用预填充数据库

我们将构建一个数据库并将其放入我们的`asset`文件夹中，这是一个只读目录。在运行时，我们将检查数据库是否存在。如果不存在，我们将从`asset`文件夹复制我们的数据库到`/data/data/yourpackage/databases`。在第二章中，我们使用了一个名为 SQLite Manager 的工具；看一下该章的第三个屏幕截图。我们现在将使用相同的工具来构建我们的数据库。如果您按照该部分中解释的方式提取数据库或查看该屏幕截图，您将注意到除了您的数据库表之外还有一些其他表：

![使用预填充数据库](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_04_06.jpg)

创建预填充数据库的步骤如下：

1.  要创建一个预填充的数据库，我们需要创建一个名为`android_metadata`的表，除了我们需要的表。使用 SQLite Manager 工具，我们将创建一个名为`contact`的新数据库，然后我们将创建`android_metdata`表：

```kt
CREATE TABLE "android_metadata"("locale" TEXT DEFAULT 'en_US')
```

1.  我们将在表中插入一行：

```kt
INSERT INTO "android_metadata" VALUES ('en_US')
```

1.  现在我们将使用我们在第二章中使用的 SQL 查询来创建我们需要的表，即`contact_table`。在`DatabaseManager`类中，我们将只需用实际值替换常量：

```kt
CREATE TABLE "contact_table" ("_id" integer primary key autoincrement not null,"contact_name" text not null,"contact_number" text not null,"contact_email" text not null,"photo_id" BLOB )
```

如果尚未定义，有必要将我们表的主 ID 字段重命名为`_id`。这有助于 Android 识别我们表的 ID 字段绑定位置。

1.  让我们填写一些数据行。我们可以通过运行`Insert`查询或使用该工具手动输入值来完成。现在，将数据库文件复制到`asset`文件夹中。

1.  现在，在我们原始的个人联系人管理器中，我们将修改我们的`DatabaseManager`类。好处是这是我们唯一需要修改的类，系统的其余部分将按预期工作。

1.  当应用程序运行并通过传递上下文创建一个新的`DatabaseManager`类时，我们将调用`createDatabase()`，首先我们将检查数据库是否已经存在：

```kt
Private Boolean checkDataBase()
{
  SQLiteDatabase checkDB = null;
  try {
     String myPath = DB_PATH + DB_NAME;
     checkDB = SQLiteDatabase.openDatabase(myPath, null,
         SQLiteDatabase.OPEN_READONLY);
  } catch (SQLiteException e) {
     // database doesn't exist yet.
  }
  if (checkDB != null) {
     checkDB.close();
  }
  return checkDB != null ? true : false;
}
```

1.  如果没有，我们将创建一个空数据库，然后将其替换为我们从`asset`文件夹中复制的数据库。从`asset`文件夹复制数据库后，我们将创建一个新的`SQLiteDatabase`对象：

```kt
private void copyDataBase() throws IOException
{
  InputStream myInput = myContext.getAssets().open(DB_NAME);
  String outFileName = DB_PATH + DB_NAME;
  OutputStream myOutput = new FileOutputStream(outFileName);
  byte[] buffer = new byte[1024];
  int length;
  while ((length = myInput.read(buffer)) > 0) {
     myOutput.write(buffer, 0, length);
  }

  myOutput.flush();
  myOutput.close();
  myInput.close();
}
```

另一个要注意的是，我们的`CustomSQLiteOpenHelper`类的`onCreate()`方法将是空的，因为我们不是在创建数据库和表，而是在复制一个。示例代码捆绑在`第四章`的代码包中。如果这个过程看起来很繁琐，不用担心；Android 开发者社区为您提供了解决方案。SQLiteAssetHelper 是一个 Android 库，将帮助您管理数据库的创建和版本管理，使用应用程序的原始资产文件。

要实现这一点，我们必须遵循一些简单的步骤：

1.  将 JAR 文件复制到我们项目的`libs`文件夹中。

1.  将库添加到 Java 构建路径中。

1.  将我们的压缩数据库文件复制到`projectassets/databases/your_database.db.zip`的`asset`文件夹中。

1.  ZIP 文件应该只包含一个`db`文件。

1.  不要扩展框架的`SQLiteOpenHelper`类，而是扩展`SQLiteAssetHelper`类。

1.  他们还为您提供升级数据库文件的帮助，该文件需要放在`assets/databases/<database_name>_upgrade_<from_version>-<to_version>.sql`中。

1.  该库、文档及其相应的示例可在[`goo.gl/8XSSmR`](http://goo.gl/8XSSmR)找到。

# 总结

在本章中，我们涵盖了许多高级主题，从加载程序到数据安全性。我们实现了我们的游标加载程序，以了解加载程序如何为我们的应用程序带来魔力，并深入了解了如何保护我们的数据库以及在向其他应用程序公开内容提供程序时理解权限的概念。我们还介绍了一些技巧，比如使用预填充数据库进行发货，升级数据库而不破坏系统，以及在不使用 SQL 命令的情况下使用数据库查询。这绝不是我们可以通过数据库和 Android 实现的唯一一组事物。本章只是对广阔的编程可能性的一个推动。
