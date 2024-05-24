# SpringBoot2 和 React 全栈开发实用指南（三）

> 原文：[`zh.annas-archive.org/md5/B5164CAFF262E48113020BA46AD77AF2`](https://zh.annas-archive.org/md5/B5164CAFF262E48113020BA46AD77AF2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：添加 CRUD 功能

本章描述了如何在我们的前端实现 CRUD 功能。我们将使用第八章中学到的组件，*React 有用的第三方组件*。我们将从后端获取数据并在表中呈现数据。然后，我们将实现删除、编辑和添加功能。最后，我们将添加功能以将数据导出到 CSV 文件。

在本章中，我们将讨论以下内容：

+   如何从后端获取数据并在前端呈现数据

+   如何使用 REST API 删除、添加和更新数据

+   如何向用户显示提示消息

+   如何从 React 应用程序导出数据到 CSV 文件

# 技术要求

我们在第四章中创建的 Spring Boot 应用程序需要与上一章的修改（未经保护的后端）一起使用。

我们还需要在上一章中创建的 React 应用程序（*carfront*）。

# 创建列表页面

在第一阶段，我们将创建列表页面，显示带分页、过滤和排序功能的汽车。运行 Spring Boot 后端，可以通过向`http://localhost:8080/api/cars` URL 发送`GET`请求来获取汽车，如第三章中所示，*使用 Spring Boot 创建 RESTful Web 服务*。

让我们检查来自响应的 JSON 数据。汽车数组可以在 JSON 响应数据的`_embedded.cars`节点中找到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/27d377c2-2c0b-455c-9b8d-fbef6d11dc77.png)

现在，一旦我们知道如何从后端获取汽车，我们就准备好实现列表页面来显示汽车。以下步骤描述了这一实践：

1.  打开 VS Code 中的*carfront* React 应用程序（在上一章中创建的 React 应用程序）。

1.  当应用程序有多个组件时，建议为它们创建一个文件夹。在`src`文件夹中创建一个名为`components`的新文件夹。使用 VS Code，可以通过右键单击侧边栏文件资源管理器中的文件夹，并从菜单中选择“新建文件夹”来创建文件夹：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/4220c9db-f9b3-4913-85ad-4e4be3c236c8.png)

1.  在`components`文件夹中创建一个名为`Carlist.js`的新文件，现在您的项目结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/e8c93710-5edb-4ec9-9382-b511dfa8eebd.png)

1.  在编辑器视图中打开`Carlist.js`文件，并编写组件的基本代码，如下所示：

```java
import React, { Component } from 'react';

class Carlist extends Component {

  render() {
    return (
      <div></div>
    );
  }
}

export default Carlist;
```

1.  我们需要一个从 REST API 获取的`cars`状态，因此，我们必须添加构造函数并定义一个数组类型的状态值：

```java
constructor(props) {
  super(props);
  this.state = { cars: []};
} 
```

1.  在`componentDidMount()`生命周期方法中执行`fetch`。来自 JSON 响应数据的汽车将保存到名为`cars`的状态中：

```java
  componentDidMount() {
    fetch('http://localhost:8080/api/cars')
    .then((response) => response.json()) 
    .then((responseData) => { 
      this.setState({ 
        cars: responseData._embedded.cars,
      }); 
    })
    .catch(err => console.error(err)); 
  }
```

1.  使用 map 函数将`car`对象转换为`render()`方法中的表行，并添加表元素：

```java
render() {
  const tableRows = this.state.cars.map((car, index) => 
    <tr key={index}>
      <td>{car.brand}</td>
      <td>{car.model}</td>
      <td>{car.color}</td>
      <td>{car.year}</td>
      <td>{car.price}</td>
    </tr>
  );

  return (
    <div className="App">
      <table>
        <tbody>{tableRows}</tbody>
      </table>
    </div>
  );
}
```

现在，如果使用`npm start`命令启动 React 应用程序，应该会看到以下列表页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d7177ba7-c83d-4e98-8b66-166f71de7a2c.png)

当我们创建更多的 CRUD 功能时，URL 服务器可能会重复多次，并且当后端部署到本地主机以外的服务器时，它将发生变化。因此，最好将其定义为常量。然后，当 URL 值更改时，我们只需在一个地方进行修改。让我们在我们应用程序的根文件夹中创建一个名为`constants.js`的新文件。在编辑器中打开文件，并将以下行添加到文件中：

```java
export const SERVER_URL = 'http://localhost:8080/'
```

然后，我们将其导入到我们的`Carlist.js`文件中，并在`fetch`方法中使用它：

```java
//Carlist.js
// Import server url (named import)
import {SERVER_URL} from '../constants.js'

// Use imported constant in the fetch method
fetch(SERVER_URL + 'api/cars')
```

最后，您的`Carlist.js`文件源代码应如下所示：

```java
import React, { Component } from 'react';
import {SERVER_URL} from '../constants.js'

class Carlist extends Component {
  constructor(props) {
    super(props);
    this.state = { cars: []};
  }

  componentDidMount() {
    fetch(SERVER_URL + 'api/cars')
    .then((response) => response.json()) 
    .then((responseData) => { 
      this.setState({ 
        cars: responseData._embedded.cars,
      }); 
    })
    .catch(err => console.error(err)); 
  }

  render() {
    const tableRows = this.state.cars.map((car, index) => 
      <tr key={index}><td>{car.brand}</td>
       <td>{car.model}</td><td>{car.color}</td>
       <td>{car.year}</td><td>{car.price}</td></tr>);

    return (
      <div className="App">
        <table><tbody>{tableRows}</tbody></table>
      </div>
    );
  }
}

export default Carlist;
```

现在我们将使用 React Table 来获得分页、过滤和排序功能。通过在终端中按*Ctrl* + *C*停止开发服务器，并输入以下命令来安装 React Table。安装完成后，重新启动应用程序：

```java
npm install react-table --save
```

将`react-table`和样式表导入到您的`Carlist.js`文件中：

```java
import ReactTable from "react-table";
import 'react-table/react-table.css';
```

然后从`render()`方法中删除`table`和`tableRows`。React Table 的`data`属性是`this.state.cars`，其中包含获取的汽车。我们还必须定义表的`columns`，其中`accessor`是`car`对象的字段，`header`是标题的文本。为了启用过滤，我们将表的`filterable`属性设置为`true`。请参阅以下`render()`方法的源代码：

```java
  render() {
    const columns = [{
      Header: 'Brand',
      accessor: 'brand'
    }, {
      Header: 'Model',
      accessor: 'model',
    }, {
      Header: 'Color',
      accessor: 'color',
    }, {
      Header: 'Year',
      accessor: 'year',
    }, {
      Header: 'Price €',
      accessor: 'price',
    },]

    return (
      <div className="App">
        <ReactTable data={this.state.cars} columns={columns} 
          filterable={true}/>
      </div>
    );
  }
```

使用 React Table 组件，我们用少量的编码获得了表的所有必要功能。现在列表页面看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/5927d0cc-a2d0-4d90-8dda-f203e09642bd.png)

# 删除功能

可以通过向`http://localhost:8080/api/cars/[carid]`端点发送`DELETE`方法请求从数据库中删除项目。如果我们查看 JSON 响应数据，我们可以看到每辆汽车都包含一个指向自身的链接，并且可以从`_links.self.href`节点访问，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/aef91708-ffd8-47d3-823e-4dbd5f442a13.png)

以下步骤显示了如何实现删除功能：

1.  我们将为表中的每一行创建一个按钮，按钮的访问器将是`_links.self.href`，我们可以使用它来调用我们即将创建的删除函数。但首先，使用`Cell`向表中添加一个新列来渲染按钮。请参阅以下源代码。我们不希望为按钮列启用排序和过滤，因此这些属性被设置为`false`。按钮在按下时调用`onDelClick`函数，并将汽车的链接作为参数发送：

```java
  const columns = [{
    Header: 'Brand',
    accessor: 'brand'
  }, {
    Header: 'Model',
    accessor: 'model',
  }, {
    Header: 'Color',
    accessor: 'color',
  }, {
    Header: 'Year',
    accessor: 'year',
  }, {
    Header: 'Price €',
    accessor: 'price',
  }, {
    id: 'delbutton',
    sortable: false,
    filterable: false,
    width: 100,
    accessor: '_links.self.href',
    Cell: ({value}) => (<button onClick={()=>{this.onDelClick(value)}}>Delete</button>)
  }]
```

1.  实现`onDelClick`函数。但首先，让我们从`componentDidMount()`方法中取出`fetchCars`函数。这是因为我们希望在汽车被删除后也调用`fetchCars`函数，以向用户显示更新后的汽车列表。创建一个名为`fetchCars()`的新函数，并将`componentDidMount()`方法中的代码复制到新函数中。然后从`componentDidMount()`函数中调用`fetchCars()`函数以最初获取汽车：

```java
componentDidMount() {
  this.fetchCars();
}

fetchCars = () => {
  fetch(SERVER_URL + 'api/cars')
  .then((response) => response.json()) 
  .then((responseData) => { 
    this.setState({ 
      cars: responseData._embedded.cars,
    }); 
  })
  .catch(err => console.error(err)); 
}
```

1.  实现`onDelClick`函数。我们向汽车链接发送`DELETE`请求，当删除成功删除时，我们通过调用`fetchCars()`函数刷新列表页面：

```java
// Delete car
onDelClick = (link) => {
  fetch(link, {method: 'DELETE'})
  .then(res => this.fetchCars())
  .catch(err => console.error(err)) 
}
```

当您启动应用程序时，前端应该如下截图所示，当按下删除按钮时，汽车将从列表中消失：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/51abe6e2-ba35-493e-8bcf-17b84d6affc1.png)

在成功删除或出现错误时，向用户显示一些反馈会很好。让我们实现一个提示消息来显示删除的状态。为此，我们将使用`react-toastify`组件（[`github.com/fkhadra/react-toastify`](https://github.com/fkhadra/react-toastify)）。通过在您使用的终端中键入以下命令来安装该组件：

```java
npm install react-toastify --save
```

安装完成后，启动您的应用程序并在编辑器中打开`Carlist.js`文件。我们必须导入`ToastContainer`、`toast`和样式表以开始使用`react-toastify`。将以下导入语句添加到您的`Carlist.js`文件中：

```java
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
```

`ToastContainer`是用于显示提示消息的容器组件，应该在`render()`方法中。在`ToastContainer`中，您可以使用`autoClose`属性以毫秒为单位定义提示消息的持续时间。在`render()`方法的返回语句中添加`ToastContainer`组件，就在`ReactTable`之后：

```java
return (
  <div className="App">
     <ReactTable data={this.state.cars} columns={columns} 
       filterable={true}/>
     <ToastContainer autoClose={1500} } /> 
   </div>
);
```

然后，我们将在`onDelClick()`函数中调用 toast 方法来显示提示消息。您可以定义消息的类型和位置。成功删除时显示成功消息，在出现错误时显示错误消息：

```java
// Delete car
onDelClick = (link) => {
  fetch(link, {method: 'DELETE'})
  .then(res => {
    toast.success("Car deleted", {
      position: toast.POSITION.BOTTOM_LEFT
    });
    this.fetchCars();
  })
  .catch(err => {
    toast.error("Error when deleting", {
      position: toast.POSITION.BOTTOM_LEFT
    });
    console.error(err)
  }) 
 }
```

现在，当汽车被删除时，您将看到提示消息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/b87b9982-af5f-4dd7-a391-1e57928865c1.png)

为了避免意外删除汽车，按下删除按钮后最好有一个确认对话框。我们将使用`react-confirm-alert`组件（[`github.com/GA-MO/react-confirm-alert`](https://github.com/GA-MO/react-confirm-alert)）来实现这一点。如果您的应用程序正在运行，请通过在终端中按下*Ctrl* + *C*来停止开发服务器，并输入以下命令来安装`react-confirm-alert`。安装后，重新启动应用程序：

```java
npm install react-confirm-alert --save
```

将`confirmAlert`和 CSS 文件导入`Carlist`组件：

```java
import { confirmAlert } from 'react-confirm-alert';
import 'react-confirm-alert/src/react-confirm-alert.css' 
```

创建一个名为`confirmDelete`的新函数，用于打开确认对话框。如果对话框的“是”按钮被按下，将调用`onDelClick`函数并删除汽车：

```java
confirmDelete = (link) => {
  confirmAlert({
    message: 'Are you sure to delete?',
    buttons: [
      {
        label: 'Yes',
        onClick: () => this.onDelClick(link)
      },
      {
        label: 'No',
      }
    ]
  })
}
```

然后，将删除按钮的`onClick`事件中的函数更改为`confirmDelete`：

```java
render() {
  const columns = [{
    Header: 'Brand',
    accessor: 'brand',
  }, {
    Header: 'Model',
    accessor: 'model',
  }, {
    Header: 'Color',
    accessor: 'color',
  }, {
    Header: 'Year',
    accessor: 'year',
  }, {
    Header: 'Price €',
    accessor: 'price',
  }, {
    id: 'delbutton',
    sortable: false,
    filterable: false,
    width: 100,
    accessor: '_links.self.href',
    Cell: ({value}) => (<button onClick=
      {()=>{this.confirmDelete(value)}}>Delete</button>)
  }]
```

如果您现在按下删除按钮，确认对话框将被打开，只有当您按下“是”按钮时，汽车才会被删除：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/bd642b3c-6dea-4b0e-9036-33c540bf8ca2.png)

# 添加功能

下一步是为前端创建添加功能。我们将使用 React Skylight 模态组件来实现这一点。我们已经介绍了在第八章中使用 React Skylight 的用法，*React 的有用的第三方组件*。我们将在用户界面中添加“新车”按钮，当按下时打开模态表单。模态表单包含保存汽车所需的所有字段，以及用于保存和取消的按钮。

通过在终端中按下*Ctrl* + *C*来停止开发服务器，并输入以下命令来安装 React Skylight。安装后，重新启动应用程序：

```java
npm install react-skylight --save 
```

以下步骤显示了如何使用模态表单组件创建添加功能：

1.  在`components`文件夹中创建一个名为`AddCar.js`的新文件，并将组件类基本代码写入文件中，如下所示。添加`react-skylight`组件的导入：

```java
import React from 'react';
import SkyLight from 'react-skylight';

class AddCar extends React.Component {
  render() {
    return (
      <div>
      </div> 
    );
  }
}

export default AddCar;
```

1.  引入一个包含所有汽车字段的状态：

```java
constructor(props) {
   super(props);
   this.state = {brand: '', model: '', year: '', color: '', price: ''};
}
```

1.  在`render()`方法中添加一个表单。表单包含`ReactSkylight`模态表单组件，其中包含按钮和收集汽车数据所需的输入字段。打开模态窗口的按钮将显示在 carlist 页面上，必须在`ReactSkylight`之外。所有输入字段都应该有一个`name`属性，其值与将保存值的状态的名称相同。输入字段还具有`onChange`处理程序，通过调用`handleChange`函数将值保存到状态：

```java
handleChange = (event) => {
   this.setState(
     {[event.target.name]: event.target.value}
   );
}

render() {
    return (
      <div>
        <SkyLight hideOnOverlayClicked ref="addDialog">
          <h3>New car</h3>
          <form>
            <input type="text" placeholder="Brand" name="brand" 
              onChange={this.handleChange}/><br/> 
            <input type="text" placeholder="Model" name="model" 
              onChange={this.handleChange}/><br/>
            <input type="text" placeholder="Color" name="color" 
              onChange={this.handleChange}/><br/>
            <input type="text" placeholder="Year" name="year" 
              onChange={this.handleChange}/><br/>
            <input type="text" placeholder="Price" name="price" 
              onChange={this.handleChange}/><br/>
            <button onClick={this.handleSubmit}>Save</button>
            <button onClick={this.cancelSubmit}>Cancel</button>     
          </form> 
        </SkyLight>
        <div>
            <button style={{'margin': '10px'}} 
              onClick={() => this.refs.addDialog.show()}>New car</button>
        </div>
      </div> 
    );
```

1.  将`AddCar`组件插入`Carlist`组件中，以查看是否可以打开该表单。打开`Carlist.js`文件以查看编辑器视图，并导入`AddCar`组件：

```java
import AddCar from './AddCar.js';
```

1.  在`Carlist.js`文件中实现`addCar`函数，该函数将向后端`api/cars`端点发送`POST`请求。请求将包括新的`car`对象在主体内以及`'Content-Type': 'application/json'`头。需要头部是因为使用`JSON.stringify()`方法将`car`对象转换为 JSON 格式：

```java
// Add new car
addCar(car) {
  fetch(SERVER_URL + 'api/cars', 
    { method: 'POST', 
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(car)
    })
  .then(res => this.fetchCars())
  .catch(err => console.error(err))
} 
```

1.  将`AddCar`组件添加到`render()`方法中，并将`addCar`和`fetchCars`函数作为 props 传递给`AddCar`组件，允许我们从`AddCar`组件中调用这些函数。现在`CarList.js`文件的返回语句应该如下所示：

```java
// Carlist.js 
return (
  <div className="App">
    <AddCar addCar={this.addCar} fetchCars={this.fetchCars}/>
    <ReactTable data={this.state.cars} columns={columns} 
      filterable={true} pageSize={10}/>
    <ToastContainer autoClose={1500}/> 
  </div>
);
```

如果您启动前端应用程序，它现在应该看起来像下面这样，如果您按下“新车”按钮，它应该打开模态表单：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7eb5802d-b483-43b6-adc5-a62f49c003d1.png)

1.  在`AddCar.js`文件中实现`handleSubmit`和`cancelSubmit`函数。`handleSubmit`函数创建一个新的`car`对象并调用`addCar`函数，该函数可以通过 props 访问。`cancelSubmit`函数只是关闭模态表单。

```java
// Save car and close modal form
handleSubmit = (event) => {
   event.preventDefault();
   var newCar = {brand: this.state.brand, model: this.state.model, 
     color: this.state.color, year: this.state.year, 
     price: this.state.price};
   this.props.addCar(newCar); 
   this.refs.addDialog.hide(); 
}

// Cancel and close modal form
cancelSubmit = (event) => {
  event.preventDefault(); 
  this.refs.addDialog.hide(); 
}
```

现在，您可以通过按下“新车”按钮打开模态表单。然后，您可以填写表单数据，并按“保存”按钮。到目前为止，表单看起来不好看，但我们将在下一章中进行样式设置：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/316305a5-dd82-412d-99e8-991957c8b459.png)

列表页面已刷新，并且新车可以在列表中看到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/cfea3c1b-a3a4-42c1-b8d2-14f9c89889aa.png)

# 编辑功能

我们将通过将表格更改为可编辑并向每行添加保存按钮来实现编辑功能。保存按钮将调用向后端发送`PUT`请求以将更改保存到数据库的函数：

1.  添加单元格渲染器，将表格单元格更改为可编辑状态。打开`Carlist.js`文件并创建一个名为`renderEditable`的新函数。请参阅以下函数的源代码。单元格将是`div`元素，`contentEditable`属性使其可编辑。`suppressContentEditableWarning`抑制了当标记为可编辑的元素具有子元素时出现的警告。当用户离开表格单元格时，将执行`onBlur`中的函数，并在这里我们将更新状态：

```java
renderEditable = (cellInfo) => {
  return (
    <div
      style={{ backgroundColor: "#fafafa" }}
      contentEditable
      suppressContentEditableWarning
      onBlur={e => {
        const data = [...this.state.cars];
        data[cellInfo.index][cellInfo.column.id] = 
         e.target.innerHTML;
        this.setState({ cars: data });
      }}
      dangerouslySetInnerHTML={{
        __html: this.state.cars[cellInfo.index][cellInfo.column.id]
      }} 
    />
  );
} 
```

1.  定义要编辑的表格列。这是使用 React Table 中列的`Cell`属性完成的，该属性定义了如何呈现列的单元格：

```java
const columns = [{
  Header: 'Brand',
  accessor: 'brand',
  Cell: this.renderEditable
}, {
  Header: 'Model',
  accessor: 'model',
  Cell: this.renderEditable
}, {
  Header: 'Color',
  accessor: 'color',
  Cell: this.renderEditable
}, {
  Header: 'Year',
  accessor: 'year',
  Cell: this.renderEditable
}, {
  Header: 'Price €',
  accessor: 'price',
  Cell: this.renderEditable
}, {
  id: 'delbutton',
  sortable: false,
  filterable: false,
  width: 100,
  accessor: '_links.self.href',
  Cell: ({value}) => (<button onClick={()=>{this.onDelClick(value)}}>Delete</button>)
}]
```

现在，如果您在浏览器中打开应用程序，您会发现表格单元格是可编辑的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a540c56d-dfc3-4c54-bc82-4e80f5f45246.png)

1.  要更新汽车数据，我们必须向`http://localhost:8080/api/cars/[carid]` URL 发送`PUT`请求。链接与删除功能相同。请求包含更新后的`car`对象在请求体内，并且我们在添加功能中使用的`'Content-Type': 'application/json'`标头。创建一个名为`updateCar`的新函数，函数的源代码显示在以下代码片段中。该函数接收两个参数，更新后的`car`对象和请求 URL。成功更新后，我们将向用户显示提示消息：

```java
// Update car
updateCar(car, link) {
  fetch(link, 
  { method: 'PUT', 
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(car)
  })
  .then( res =>
    toast.success("Changes saved", {
      position: toast.POSITION.BOTTOM_LEFT
    }) 
  )
  .catch( err => 
    toast.error("Error when saving", {
      position: toast.POSITION.BOTTOM_LEFT
    }) 
  )
}
```

1.  将“保存”按钮添加到表格行。当用户按下按钮时，它调用`updateCar`函数并传递两个参数。第一个参数是`row`，它是行中所有值的`object（=car object）`。第二个参数是`value`，它设置为`_links.href.self`，这将是我们在请求中需要的汽车的 URL：

```java
const columns = [{
  Header: 'Brand',
  accessor: 'brand',
  Cell: this.renderEditable
}, {
  Header: 'Model',
  accessor: 'model',
  Cell: this.renderEditable
}, {
  Header: 'Color',
  accessor: 'color',
  Cell: this.renderEditable
}, {
  Header: 'Year',
  accessor: 'year',
  Cell: this.renderEditable
}, {
  Header: 'Price €',
  accessor: 'price',
  Cell: this.renderEditable
}, {
  id: 'savebutton',
  sortable: false,
  filterable: false,
  width: 100,
  accessor: '_links.self.href',
  Cell: ({value, row}) => 
    (<button onClick={()=>{this.updateCar(row, value)}}>
     Save</button>)
}, {
  id: 'delbutton',
  sortable: false,
  filterable: false,
  width: 100,
  accessor: '_links.self.href',
  Cell: ({value}) => (<button onClick=
    {()=>{this.onDelClick(value)}}>Delete</button>)
}]
```

现在，如果您编辑表格中的值并按下“保存”按钮，您应该会看到提示消息，并且更新的值将保存到数据库中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f3fd10be-4fa4-4e48-a9bd-f23e909a5933.png)

# 其他功能

我们还将实现一个功能，即将数据导出为 CSV。有一个名为`react-csv`的包（[`github.com/abdennour/react-csv`](https://github.com/abdennour/react-csv)），可用于将数据数组导出到 CSV 文件。

如果您的应用程序已启动，请通过在终端中按*Ctrl* + *C*停止开发服务器，并键入以下命令以安装`react-csv`。安装后，重新启动应用程序：

```java
npm install react-csv --save
```

`react-csv`包含两个组件—`CSVLink`和`CSVDownload`。我们将在我们的应用程序中使用第一个，因此将以下导入添加到`Carlist.js`文件中：

```java
import { CSVLink } from 'react-csv';
```

`CSVLink`组件接受`data`属性，其中包含要导出到 CSV 文件的数据数组。您还可以使用`separator`属性定义数据分隔符（默认分隔符为逗号）。在`render()`方法的`return`语句中添加`CSVLink`组件。`data`属性的值现在将是`this.state.cars`：

```java
// Carlist.js render() method
return (
  <div className="App">
    <CSVLink data={this.state.cars} separator=";">Export CSV</CSVLink>
    <AddCar addCar={this.addCar} fetchCars={this.fetchCars}/>
    <ReactTable data={this.state.cars} columns={columns} 
       filterable={true} pageSize={10}/>
    <ToastContainer autoClose={6500}/> 
  </div>
);
```

在浏览器中打开应用程序，您应该在我们的应用程序中看到导出 CSV 链接。样式不好看，但我们将在下一章中处理。如果您点击链接，您将在 CSV 文件中获得数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ad3ffe91-b9e5-4b5d-b7d3-6634a2ecce7c.png)

现在所有功能都已实现。

# 总结

在本章中，我们实现了应用程序的所有功能。我们从后端获取汽车数据，并在 React Table 中显示这些数据，该表提供分页、排序和过滤功能。然后我们实现了删除功能，并使用 toast 组件向用户提供反馈。添加功能是使用 React Skylight 模态表单组件实现的。在编辑功能中，我们利用了 React Table 的可编辑表格功能。最后，我们实现了将数据导出到 CSV 文件的功能。在下一章中，我们将开始使用 Material UI 组件库来完善我们的用户界面。在下一章中，我们将使用 React Material-UI 组件库来设计我们的前端界面。

# 问题

1.  如何使用 React 的 REST API 获取和展示数据？

1.  如何使用 React 的 REST API 删除数据？

1.  如何使用 React 的 REST API 添加数据？

1.  如何使用 React 的 REST API 更新数据？

1.  如何使用 React 显示 toast 消息？

1.  如何使用 React 将数据导出到 CSV 文件？

# 进一步阅读

Packt 还有其他很棒的资源可以学习 React：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)


# 第十一章：使用 React Material-UI 对前端进行样式设置

本章将解释如何在我们的前端中使用 Material-UI 组件。我们将使用`Button`组件来显示样式化按钮。模态表单输入字段将被`TextField`组件替换，该组件具有许多很好的功能。Material-UI 提供了`Snackbar`组件，可以向最终用户显示提示消息。我们将用`Snackbar`替换`react-toastify`组件，以获得统一的外观。最后，我们将使用`AppBar`组件代替 React 应用程序标题。

在本章中，我们将查看以下内容：

+   什么是 Material-UI？

+   如何在我们的前端中使用 Material-UI 组件

+   如何在 React 应用程序中删除未使用的组件

# 技术要求

我们在第四章中创建的 Spring Boot 应用程序，*Securing and Testing Your Backend*，需要与上一章的修改（未经保护的后端）一起使用。

我们还需要在上一章中使用的 React 应用程序(*carfront*)。

# 使用 Button 组件

通过在您正在使用的终端中键入以下命令并在安装完成后启动您的应用程序来安装 Material-UI：

```java
npm install @material-ui/core --save
```

让我们首先将所有按钮更改为使用 Material-UI 的`Button`组件。将`Button`导入`AddCar.js`文件：

```java
// AddCar.js
import Button from '@material-ui/core/Button';
```

将按钮更改为使用`Button`组件。在列表页面中，我们使用主按钮，在模态表单中使用轮廓按钮：

```java
  render() {
    return (
      <div>
        <SkyLight hideOnOverlayClicked ref="addDialog">
          <h3>New car</h3>
          <form>
            <input type="text" placeholder="Brand" name="brand" 
            onChange={this.handleChange}/><br/> 
            <input type="text" placeholder="Model" name="model" 
            onChange={this.handleChange}/><br/>
            <input type="text" placeholder="Color" name="color" 
            onChange={this.handleChange}/><br/>
            <input type="text" placeholder="Year" name="year" 
            onChange={this.handleChange}/><br/>
            <input type="text" placeholder="Price" name="price" 
            onChange={this.handleChange}/><br/><br/>
            <Button variant="outlined" color="primary" 
            onClick={this.handleSubmit}>Save</Button> 
            <Button variant="outlined" color="secondary" 
            onClick={this.cancelSubmit}>Cancel</Button> 
          </form> 
        </SkyLight>
        <div>
            <Button variant="raised" color="primary" 
            style={{'margin': '10px'}} 
            onClick={() => this.refs.addDialog.show()}>
            New Car</Button>
        </div>
      </div> 
    );
```

现在，列表页面按钮应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f33d2eef-220c-40e8-8894-bbd3c1114522.png)

模态表单按钮应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/35a9f5bc-474c-4d50-822d-6dd4b925c526.png)

我们在汽车表中使用了平面变体按钮，并将按钮大小定义为小。请参见以下表列的源代码：

```java
// Carlist.js render() method
const columns = [{
  Header: 'Brand',
  accessor: 'brand',
  Cell: this.renderEditable
}, {
  Header: 'Model',
  accessor: 'model',
  Cell: this.renderEditable
}, {
  Header: 'Color',
  accessor: 'color',
  Cell: this.renderEditable
}, {
  Header: 'Year',
  accessor: 'year',
  Cell: this.renderEditable
}, {
  Header: 'Price €',
  accessor: 'price',
  Cell: this.renderEditable
}, {
  id: 'savebutton',
  sortable: false,
  filterable: false,
  width: 100,
  accessor: '_links.self.href',
  Cell: ({value, row}) => (<Button size="small" variant="flat" color="primary" 
    onClick={()=>{this.updateCar(row, value)}}>Save</Button>)
}, {
  id: 'delbutton',
  sortable: false,
  filterable: false,
  width: 100,
  accessor: '_links.self.href',
  Cell: ({value}) => (<Button size="small" variant="flat" color="secondary" 
    onClick={()=>{this.confirmDelete(value)}}>Delete</Button>)
}]
```

现在，表格应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/47a0a03d-70cb-4b6e-9cbe-be77136b3663.png)

# 使用 Grid 组件

Material-UI 提供了一个`Grid`组件，可用于为您的 React 应用程序获取网格布局。我们将使用`Grid`来获取新项目按钮和导出 CSV 链接在同一行上。

将以下导入添加到`Carlist.js`文件中以导入`Grid`组件：

```java
import Grid from '@material-ui/core/Grid';
```

接下来，我们将`AddCar`和`CSVLink`包装在`Grid`组件中。`Grid`组件有两种类型——容器和项目。这两个组件都包装在项目的`Grid`组件中。然后，两个项目的`Grid`组件都包装在容器的`Grid`组件中：

```java
// Carlist.js render() method
return (
  <div className="App">
    <Grid container>
      <Grid item>
        <AddCar addCar={this.addCar} fetchCars={this.fetchCars}/>
      </Grid>
      <Grid item style={{padding: 20}}>
         <CSVLink data={this.state.cars} separator=";">Export CSV</CSVLink>
      </Grid>
    </Grid>

    <ReactTable data={this.state.cars} columns={columns} 
      filterable={true} pageSize={10}/>
    <ToastContainer autoClose={1500}/> 
  </div>
);
```

现在，您的应用程序应该如下所示，按钮现在放在一行中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/465517bb-5cf3-4f10-9462-c3c3fb612f14.png)

# 使用 TextField 组件

在这一部分，我们将使用 Material-UI 的`TextField`组件来更改模态表单中的文本输入。将以下导入语句添加到`AddCar.js`文件中：

```java
import TextField from '@material-ui/core/TextField';
```

然后，在表单中将输入更改为`TextField`组件。我们使用`label`属性来设置`TextField`组件的标签：

```java
render() {
  return (
    <div>
      <SkyLight hideOnOverlayClicked ref="addDialog">
        <h3>New car</h3>
        <form>
          <TextField label="Brand" placeholder="Brand" 
            name="brand" onChange={this.handleChange}/><br/> 
          <TextField label="Model" placeholder="Model" 
            name="model" onChange={this.handleChange}/><br/>
          <TextField label="Color" placeholder="Color" 
            name="color" onChange={this.handleChange}/><br/>
          <TextField label="Year" placeholder="Year" 
            name="year" onChange={this.handleChange}/><br/>
          <TextField label="Price" placeholder="Price" 
            name="price" onChange={this.handleChange}/><br/><br/>
          <Button variant="outlined" color="primary" 
            onClick={this.handleSubmit}>Save</Button> 
          <Button variant="outlined" color="secondary" 
            onClick={this.cancelSubmit}>Cancel</Button> 
        </form> 
      </SkyLight>
      <div>
         <Button variant="raised" color="primary" 
            style={{'margin': '10px'}} 
            onClick={() => this.refs.addDialog.show()}>New Car</Button>
      </div>
    </div> 
  );
```

修改后，模态表单应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ae223655-273e-4404-b0cd-dd0c33451b30.png)

# 使用 AppBar 组件

在这一部分，我们将用`AppBar`组件替换 React 应用程序标题。导入`AppBar`和`Toolbar`组件：

```java
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
```

从`App.js`文件中删除`div`标题元素。将`AppBar`组件添加到`render()`方法中，并将`Toolbar`组件放在其中。`Toolbar`组件包含应用栏中显示的文本：

```java
// App.js
import React, { Component } from 'react';
import './App.css';
import Carlist from './components/Carlist';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';

class App extends Component {
  render() {
    return (
      <div className="App">
        <AppBar position="static" color="default">
          <Toolbar>CarList</ Toolbar>
        </ AppBar>
        <Carlist /> 
      </div>
    );
  }
}

export default App;
```

现在，您的前端应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/aae8422f-e176-4c07-8031-2f152314b4eb.png)

# 使用 SnackBar 组件

我们已经通过使用`react-toastify`组件实现了提示消息。Material-UI 提供了一个名为`SnackBar`的组件，可以用于向最终用户显示消息。为了在我们的应用程序中获得统一的外观，让我们使用该组件来显示消息。

我们现在可以从`Carlist.js`文件中移除`react-toastify`的导入，也可以通过在你正在使用的终端中输入以下命令来移除组件：

```java
npm remove react-toastify
```

要开始使用`Snackbar`组件，请将以下导入添加到`Carlist.js`文件中：

```java
import Snackbar from '@material-ui/core/Snackbar';
```

我们需要为`Snackbar`添加两个新的状态值，一个用于消息，一个用于状态。将这两个状态值添加到构造函数中。状态值称为`open`，它定义了`Snackbar`是否可见：

```java
constructor(props) {
  super(props);
  this.state = { cars: [], open: false, message: ''};
}
```

然后，我们将`Snackbar`组件添加到`render()`方法中。`autoHideDuration`属性定义了在调用`onClose`之前等待的毫秒数。要显示`Snackbar`，我们只需要将`open`状态值设置为`true`并设置消息：

```java
// Carlist.js render() method's return statement
return (
  <div className="App">
    <Grid container>
      <Grid item>
        <AddCar addCar={this.addCar} fetchCars={this.fetchCars}/>
      </Grid>
      <Grid item style={{padding: 20}}>
        <CSVLink data={this.state.cars} separator=";">Export CSV</CSVLink>
      </Grid>
    </Grid>

    <ReactTable data={this.state.cars} columns={columns} 
      filterable={true} pageSize={10}/>
    <Snackbar 
      style = {{width: 300, color: 'green'}}
      open={this.state.open} onClose={this.handleClose} 
      autoHideDuration={1500} message={this.state.message} />
  </div>
);
```

接下来，我们必须实现`handleClose`函数，该函数在`onClose`事件中调用。该函数只是将`open`状态值设置为`false`：

```java
handleClose = (event, reason) => {
  this.setState({ open: false });
};
```

然后，我们用`setState()`方法替换了 toast 消息，该方法将`open`值设置为`true`，并将显示的文本设置为`message`状态：

```java
// Delete car
onDelClick = (link) => {
  fetch(link, {method: 'DELETE'})
  .then(res => {
    this.setState({open: true, message: 'Car deleted'});
    this.fetchCars();
  })
  .catch(err => {
    this.setState({open: true, message: 'Error when deleting'});
    console.error(err)
  }) 
}

// Update car
updateCar(car, link) {
  fetch(link, 
  { method: 'PUT', 
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(car)
  })
  .then( res =>
    this.setState({open: true, message: 'Changes saved'})
  )
  .catch( err => 
    this.setState({open: true, message: 'Error when saving'})
  )
}

```

以下是使用`Snackbar`组件显示消息的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f67dde87-4b2d-4b17-b4a5-fc4accfafaa3.png)

# 总结

在本章中，我们使用 Material-UI 完成了我们的前端。Material-UI 是实现了 Google 的 Material Design 的 React 组件库。我们用 Material-UI 的`Button`组件替换了所有按钮。我们使用 Material-UI 的`TextField`组件为我们的模态表单赋予了新的外观。我们移除了 React 应用程序标题，改用了`AppBar`组件。现在，向最终用户显示的消息使用`Snackbar`组件。经过这些修改，我们的前端看起来更加专业和统一。在下一章中，我们将专注于前端测试。

# 问题

1.  什么是 Material-UI？

1.  你应该如何使用不同的 Material-UI 组件？

1.  你应该如何移除未使用的组件？

# 进一步阅读

Packt 还有其他很好的资源可以学习 React：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)


# 第十二章：测试您的前端

本章解释了测试 React 应用程序的基础知识。我们将概述使用 Jest，这是 Facebook 开发的 JavaScript 测试库。我们还将介绍 Enzyme，这是由 Airbnb 开发的用于 React 的测试实用程序。我们将看看如何创建新的测试套件和测试。我们还将介绍如何运行测试并发现测试的结果。

在本章中，我们将看以下内容：

+   Jest 的基础知识

+   如何创建新的测试套件和测试

+   Enzyme 测试实用程序的基础知识

+   如何安装 Enzyme

+   如何使用 Enzyme 创建测试

# 技术要求

我们需要在第四章中创建的 Spring Boot 应用程序，*Securing and Testing Your Backend*（GitHub：[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%204`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%204)）。

我们还需要在上一章中使用的 React 应用程序（GitHub：[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%2011`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%2011)）。

# 使用 Jest

Jest 是一个用于 JavaScript 的测试库，由 Facebook 开发（[`facebook.github.io/jest/en/`](https://facebook.github.io/jest/en/)）。Jest 广泛用于 React，并为测试提供了许多有用的功能。您可以创建快照测试，从中可以获取 React 树的快照并调查状态的变化。Jest 还具有模拟功能，您可以使用它来测试例如异步 REST API 调用。Jest 还提供了在测试用例中所需的断言函数。

我们将首先看看如何为基本的 JavaScript 函数创建一个简单的测试用例，该函数执行一些简单的计算。以下函数以两个数字作为参数，并返回数字的乘积：

```java
// multi.js
export const calcMulti = (x, y) => {
    x * y;
}
```

以下代码显示了前述函数的 Jest 测试。测试用例从运行测试用例的`test`方法开始。`test`方法有一个别名，称为`it`，我们稍后在 React 示例中将使用它。测试方法获取两个必需的参数-测试名称和包含测试的函数。当您想要测试值时，使用`expect`。`toBe`是所谓的匹配器，用于检查函数的结果是否等于匹配器中的值。Jest 中有许多不同的匹配器可用，您可以从其文档中找到这些：

```java
// multi.test.js
import {calcMulti} from './multi';

test('2 * 3 equals 6', () => {
  expect(calcMulti(2, 3)).toBe(6);
});
```

Jest 与`create-react-app`一起提供，因此我们无需进行任何安装或配置即可开始测试。建议为测试文件创建一个名为`_test_`的文件夹。测试文件应具有`.test.js`扩展名。如果您在 VS Code 文件资源管理器中查看 React 前端，您会发现在`src`文件夹中已经自动创建了一个测试文件，名为`App.test.js`。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/84990f7e-069e-4734-8e76-798df3aaa5d0.png)

测试文件的源代码如下：

```java
import React from 'react';
import ReactDOM from 'react-dom';
import App from './App';

it('renders without crashing', () => {
  const div = document.createElement('div');
  ReactDOM.render(<App />, div);
  ReactDOM.unmountComponentAtNode(div);
});
```

以下测试文件创建了一个`div`元素到 DOM 并将`App`组件挂载到它上。最后，组件从`div`中卸载。因此，它只是测试您的`App`组件是否可以渲染并且测试运行程序是否正常工作。`it`是 Jest 中`test`函数的别名，第一个参数是测试的名称，第二个参数是要执行和测试的函数。

您可以通过在终端中输入以下命令来运行测试：

```java
npm test
```

或者如果您使用 Yarn，请输入以下内容：

```java
yarn test
```

在执行完测试并且一切正常工作后，您将在终端中看到以下信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/fa09273d-48c7-4531-8a20-3ed6975966d8.png)

# 快照测试

快照测试是一个有用的工具，用于测试用户界面中是否存在不需要的更改。当执行快照测试时，Jest 会生成快照文件。下次执行测试时，将新的快照与先前的快照进行比较。如果文件内容之间存在更改，测试用例将失败，并在终端中显示错误消息。

要开始快照测试，请执行以下步骤：

1.  安装`react-test-render`包。`--save-dev`参数意味着此依赖项保存到`package.json`文件的`devDependencies`部分，仅用于开发目的。如果在安装阶段键入`npm install --production`命令，则不会安装`devDependencies`部分中的依赖项。因此，所有仅在开发阶段需要的依赖项都应使用`--save-dev`参数进行安装：

```java
npm install react-test-renderer --save-dev
```

1.  您的`package.json`文件应如下所示，并且已将新的`devDependecies`部分添加到文件中：

```java
{
  "name": "carfront",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@material-ui/core": "¹.0.0",
    "@material-ui/icons": "¹.0.0",
    "material-ui": "⁰.20.1",
    "react": "¹⁶.3.2",
    "react-confirm-alert": "².0.2",
    "react-csv": "¹.0.14",
    "react-dom": "¹⁶.3.2",
    "react-scripts": "1.1.4",
    "react-skylight": "⁰.5.1",
    "react-table": "⁶.8.2"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test --env=jsdom",
    "eject": "react-scripts eject"
  },
  "devDependencies": {
    "react-test-renderer": "¹⁶.3.2"
  }
}
```

1.  将`renderer`导入到您的测试文件中：

```java
import renderer from 'react-test-renderer';
```

让我们在`App.test.js`文件中添加一个新的快照测试用例。该测试用例将创建我们的`AddCar`组件的快照测试：

1.  将`AddCar`组件导入到我们的测试文件中：

```java
import AddCar from './components/AddCar';
```

1.  在文件中已经存在的第一个测试用例之后添加以下测试代码。该测试用例从我们的`App`组件中获取快照，然后比较快照是否与先前的快照不同：

```java
it('renders a snapshot', () => {
  const tree = renderer.create(<AddCar/>).toJSON();
  expect(tree).toMatchSnapshot();
});
```

1.  通过在终端中输入以下命令再次运行测试用例：

```java
npm test
```

1.  现在您可以在终端中看到以下消息。测试套件告诉我们测试文件的数量，测试告诉我们测试用例的数量：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/0f151a12-c3ae-4faa-a38c-9aecd4337028.png)

当首次执行测试时，将创建一个`_snapshots_`文件夹。该文件夹包含从测试用例生成的所有快照文件。现在，您可以看到已生成一个快照文件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/eb52cf51-488f-46e4-8d63-13edc8e597a7.png)

快照文件现在包含了我们的`AddCar`组件的 React 树。您可以从这里的开头看到快照文件的一部分：

```java
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`renders a snapshot 1`] = `
<div>
  <section
    className="skylight-wrapper "
  >
    <div
      className="skylight-overlay"
      onClick={[Function]}
      style={
        Object {
          "backgroundColor": "rgba(0,0,0,0.3)",
          "display": "none",
          "height": "100%",
          "left": "0px",
          "position": "fixed",
          "top": "0px",
          "transitionDuration": "200ms",
          "transitionProperty": "all",
          "transitionTimingFunction": "ease",
          "width": "100%",
          "zIndex": "99",
        }
      }
  />
...continue
```

# 使用 Enzyme

Enzyme 是用于测试 React 组件输出的 JavaScript 库，由 Airbnb 开发。Enzyme 具有一个非常好的用于 DOM 操作和遍历的 API。如果您使用过 jQuery，那么很容易理解 Enzyme API 的思想。

要开始使用 Enzyme，请执行以下步骤：

1.  通过在终端中输入以下命令进行安装。这将安装`enzyme`库和适配器库，适用于 React 版本 16\. 旧版 React 版本也有可用的适配器：

```java
npm install enzyme enzyme-adapter-react-16 --save-dev
```

1.  在`src`文件夹中创建一个名为`AddCar.test.js`的新测试文件（测试套件）。现在我们将为我们的`AddCar`组件创建一个 Enzyme 浅渲染测试。第一个测试用例渲染组件并检查是否有五个`TextInput`组件，因为应该有五个。`wrapper.find`找到渲染树中与`TextInput`匹配的每个节点。在 Enzyme 测试中，我们可以使用 Jest 进行断言，这里我们使用`toHaveLength`来检查找到的节点数是否等于五。浅渲染测试将组件作为一个单元进行测试，并不会渲染任何子组件。对于这种情况，浅渲染就足够了。否则，您也可以使用`mount`进行完整的 DOM 渲染：

```java
import React from 'react';
import AddCar from './components/AddCar';
import Enzyme, { shallow } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';

Enzyme.configure({ adapter: new Adapter() });

describe('<AddCar />', () => {
  it('renders five <TextInput /> components', () => {
    const wrapper = shallow(<AddCar />);
    expect(wrapper.find('TextField')).toHaveLength(5);
  });
});
```

1.  现在，如果您运行测试，您可以在终端中看到以下消息。您还可以看到测试套件的数量为两，因为有新的测试文件并且所有测试都通过了：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/42d35766-4774-4990-9b63-0f46415c4de0.png)

您还可以使用`simulate`方法使用 Enzyme 测试事件。以下示例显示了如何测试`AddCar`组件中`TextField`品牌的`onChange`事件。此示例还显示了如何访问组件的状态。我们首先使用`wrapper.find`查找第一个`TextField`，用于汽车品牌。然后，我们设置`TextField`的值，并使用`simulate`方法模拟更改事件。最后，我们检查品牌状态的值，该值现在应该包含`Ford`：

```java
describe('<AddCar />', () => {
  it('test onChange', () => {
    const wrapper = shallow(<AddCar />);
    const brandInput = wrapper.find('TextField').get(0);
    brandInput.instance().value = 'Ford';
    usernameInput.simulate('change');
    expect(wrapper.state('brand')).toEqual('Ford');
  });
});
```

# 摘要

在本章中，我们对如何测试 React 应用程序进行了基本概述。Jest 是 Facebook 开发的一个测试库，因为我们使用`create-react-app`创建了我们的应用程序，所以它已经可用于我们的前端。我们使用 Jest 创建了一些测试，并运行这些测试，以查看如何检查测试的结果。我们安装了 Enzyme，这是一个用于 React 的测试工具。使用 Enzyme，您可以轻松测试 React 组件的渲染和事件。在下一章中，我们将保护我们的应用程序，并在前端添加登录功能。

# 问题

1.  Jest 是什么？

1.  您应该如何使用 Jest 创建测试用例？

1.  您应该如何使用 Jest 创建快照测试？

1.  Enzyme 是什么？

1.  您应该如何安装 Enzyme？

1.  您应该如何使用 Enzyme 进行渲染测试？

1.  您应该如何使用 Enzyme 测试事件？

# 进一步阅读

Packt 还有其他关于学习 React 和测试的优质资源。

+   [`www.packtpub.com/web-development/react-16-tooling`](https://www.packtpub.com/web-development/react-16-tooling)

+   [`www.packtpub.com/web-development/jasmine-javascript-testing-second-edition`](https://www.packtpub.com/web-development/jasmine-javascript-testing-second-edition)


# 第十三章：保护您的应用程序

本章解释了在后端使用 JWT 身份验证时如何对前端实施身份验证。首先，我们为后端打开安全性以启用 JWT 身份验证。然后，我们为登录功能创建一个组件。最后，我们修改我们的 CRUD 功能，以在请求的`Authorization`标头中发送令牌到后端。

在本章中，我们将研究以下内容：

+   如何在前端创建登录功能

+   如何在身份验证后实现条件渲染

+   启用 JWT 身份验证时，CRUD 功能需要什么

+   如何在身份验证失败时显示消息

# 技术要求

我们在第四章中创建的 Spring Boot 应用程序，*保护和测试您的后端*（GitHub：[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%204`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%204)）。

我们在上一章中使用的 React 应用程序（GitHub：[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%2011`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%2011)）。

# 保护后端

我们已经在前端实现了对未受保护的后端的 CRUD 功能。现在，是时候再次为我们的后端打开安全性，并返回到我们在第四章中创建的版本，*保护和测试您的后端*：

1.  使用 Eclipse IDE 打开后端项目，并在编辑器视图中打开`SecurityConfig.java`文件。我们将安全性注释掉，并允许每个人访问所有端点。现在，我们可以删除该行，并从原始版本中删除注释。现在，您的`SecurityConfig.java`文件的`configure`方法应如下所示：

```java
@Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable().cors().and().authorizeRequests()
    .antMatchers(HttpMethod.POST, "/login").permitAll()
    .anyRequest().authenticated()
    .and()
    // Filter for the api/login requests
    .addFilterBefore(new LoginFilter("/login", authenticationManager()),
       UsernamePasswordAuthenticationFilter.class)
    // Filter for other requests to check JWT in header
    .addFilterBefore(new AuthenticationFilter(),
       UsernamePasswordAuthenticationFilter.class);
}
```

让我们测试一下当后端再次被保护时会发生什么。

1.  通过在 Eclipse 中按下“运行”按钮来运行后端，并从控制台视图中检查应用程序是否正确启动。通过在终端中键入`npm start`命令来运行前端，浏览器应该打开到地址`localhost:3000`。

1.  现在您应该看到列表页面和表格为空。如果您打开开发者工具，您会注意到请求以`403 Forbidden` HTTP 错误结束。这实际上是我们想要的，因为我们尚未对前端进行身份验证：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d221b71b-6510-43ce-8142-7c8e9a27a488.png)

# 保护前端

使用 JWT 对后端进行了身份验证。在第四章中，*保护和测试您的后端*，我们创建了 JWT 身份验证，并且`/login`端点允许每个人在没有身份验证的情况下访问。在前端的登录页面中，我们必须首先调用`/login`端点以获取令牌。之后，令牌将包含在我们发送到后端的所有请求中，就像在第四章中演示的那样，*保护和测试您的后端*。

让我们首先创建一个登录组件，要求用户提供凭据以从后端获取令牌：

1.  在`components`文件夹中创建一个名为`Login.js`的新文件。现在，您的前端文件结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f8c04420-2884-43b0-bce4-8beeca7f691d.png)

1.  在 VS Code 编辑器中打开文件，并将以下基本代码添加到登录组件中。我们还导入`SERVER_URL`，因为它在登录请求中是必需的：

```java
import React, { Component } from 'react';
import {SERVER_URL} from '../constants.js';

class Login extends Component {
  render() {
    return (
      <div>        
      </div>
    );
  }
}

export default Login;
```

1.  我们需要三个用于身份验证的状态值。两个用于凭据（`username`和`password`），一个布尔值用于指示身份验证状态。身份验证状态的默认值为`false`。在`constructor`中创建`constructor`并在其中引入状态：

```java
constructor(props) {
  super(props);
  this.state = {username: '', password: '', 
    isAuthenticated: false};
}
```

1.  在用户界面中，我们将使用 Material-UI 组件库，就像我们在用户界面的其余部分中所做的那样。我们需要凭据的文本字段组件和一个调用登录函数的按钮。将组件的导入添加到`login.js`文件中：

```java
import TextField from '@material-ui/core/TextField';
import Button from '@material-ui/core/Button';
```

1.  将导入的组件添加到用户界面中，方法是将它们添加到`render()`方法中。我们需要两个`TextField`组件，一个用于用户名，一个用于密码。需要一个`RaisedButton`组件来调用我们稍后将实现的`login`函数：

```java
render() {
  return (
    <div>
      <TextField name="username" placeholder="Username" 
      onChange={this.handleChange} /><br/> 
      <TextField type="password" name="password" 
       placeholder="Password" 
      onChange={this.handleChange} /><br/><br/> 
      <Button variant="raised" color="primary" 
       onClick={this.login}>
        Login
     </Button>
    </div>
  );
}
```

1.  实现`TextField`组件的更改处理程序，以将键入的值保存到状态中：

```java
handleChange = (event) => {
  this.setState({[event.target.name] : event.target.value});
}
```

1.  如第四章所示，*保护和测试您的后端*，登录是通过调用`/login`端点使用`POST`方法并在请求体内发送用户对象来完成的。如果身份验证成功，我们将在响应的`Authorization`标头中获得一个令牌。然后，我们将令牌保存到会话存储中，并将`isAuthenticated`状态值设置为`true`。会话存储类似于本地存储，但在页面会话结束时会被清除。当`isAuthenticated`状态值改变时，用户界面将被重新渲染：

```java
login = () => {
  const user = {username: this.state.username, password: this.state.password};
  fetch(SERVER_URL + 'login', {
    method: 'POST',
    body: JSON.stringify(user)
  })
  .then(res => {
    const jwtToken = res.headers.get('Authorization');
    if (jwtToken !== null) {
      sessionStorage.setItem("jwt", jwtToken);
      this.setState({isAuthenticated: true});
    }
  })
  .catch(err => console.error(err)) 
}
```

1.  我们可以实现条件渲染，如果`isAuthenticated`状态为`false`，则渲染`Login`组件，如果`isAuthenticated`状态为`true`，则渲染`Carlist`组件。我们首先必须将`Carlist`组件导入`Login`组件中：

```java
import Carlist from './Carlist';
```

然后对`render()`方法进行以下更改：

```java
render() {
  if (this.state.isAuthenticated === true) {
    return (<Carlist />)
  }
  else {
    return (
      <div>
        <TextField type="text" name="username" 
         placeholder="Username" 
        onChange={this.handleChange} /><br/> 
        <TextField type="password" name="password" 
         placeholder="Password" 
        onChange={this.handleChange} /><br/><br/> 
        <Button variant="raised" color="primary" 
         onClick={this.login}>
          Login
        </Button>
      </div>
    );
  }
}
```

1.  要显示登录表单，我们必须在`App.js`文件中渲染`Login`组件而不是`Carlist`组件：

```java
// App.js
import React, { Component } from 'react';
import './App.css';
import Login from './components/Login';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';

class App extends Component {
  render() {
    return (
      <div className="App">
        <AppBar position="static" color="default">
          <Toolbar>CarList</ Toolbar>
        </ AppBar>
        <Login /> 
      </div>
    );
  }
```

```java
}

export default App;
```

现在，当您的前端和后端正在运行时，您的前端应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/50d978f6-f9a4-4bab-b3d3-e600d1417f03.png)

如果您使用`user/user`或`admin/admin`凭据登录，您应该看到汽车列表页面。如果打开开发者工具，您会看到令牌现在保存在会话存储中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/fa1b25e3-8e29-4d64-bf20-330b0dce417c.png)

汽车列表仍然是空的，但这是正确的，因为我们还没有将令牌包含在请求中。这对于 JWT 身份验证是必需的，我们将在下一阶段实现：

1.  在 VS Code 编辑器视图中打开`Carlist.js`文件。要获取汽车，我们首先必须从会话存储中读取令牌，然后将带有令牌值的`Authorization`标头添加到请求中。您可以在此处查看获取函数的源代码：

```java
// Carlist.js 
// Fetch all cars
fetchCars = () => {
  // Read the token from the session storage
 // and include it to Authorization header
  const token = sessionStorage.getItem("jwt");
  fetch(SERVER_URL + 'api/cars', 
  {
    headers: {'Authorization': token}
  })
  .then((response) => response.json()) 
  .then((responseData) => { 
    this.setState({ 
      cars: responseData._embedded.cars,
    }); 
  })
  .catch(err => console.error(err)); 
}
```

1.  如果您登录到前端，您应该看到汽车列表中填充了来自数据库的汽车：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/e012fc8c-8e04-47ac-a9be-4fd30696ead4.png)

1.  从开发者工具中检查请求内容；您会看到它包含带有令牌值的`Authorization`标头：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/09be0970-1398-44ce-b138-f04da57cb258.png)

所有其他 CRUD 功能需要相同的修改才能正常工作。修改后，删除函数的源代码如下所示：

```java
// Delete car
onDelClick = (link) => {
  const token = sessionStorage.getItem("jwt");
  fetch(link, 
    { 
      method: 'DELETE',
      headers: {'Authorization': token}
    }
  )
  .then(res => {
    this.setState({open: true, message: 'Car deleted'});
    this.fetchCars();
  })
  .catch(err => {
    this.setState({open: true, message: 'Error when deleting'});
    console.error(err)
  }) 
}
```

修改后，添加函数的源代码如下所示：

```java
// Add new car
addCar(car) {
  const token = sessionStorage.getItem("jwt");
  fetch(SERVER_URL + 'api/cars', 
  { method: 'POST', 
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      },
      body: JSON.stringify(car)
  })
  .then(res => this.fetchCars())
  .catch(err => console.error(err))
} 
```

最后，更新函数的源代码如下所示：

```java
// Update car
updateCar(car, link) {
  const token = sessionStorage.getItem("jwt");
  fetch(link, 
  { method: 'PUT', 
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token
    },
    body: JSON.stringify(car)
  })
  .then( res =>
    this.setState({open: true, message: 'Changes saved'})
  )
  .catch( err => 
    this.setState({open: true, message: 'Error when saving'})
  )
} 
```

现在，在您登录到应用程序后，所有 CRUD 功能都可以正常工作。

在最后阶段，我们将实现一个错误消息，如果身份验证失败，将向最终用户显示该消息。我们使用 Material-UI 的`SnackBar`组件来显示消息：

1.  将以下导入添加到`Login.js`文件中：

```java
import Snackbar from '@material-ui/core/Snackbar';
```

1.  打开 Snackbar 的状态，就像我们在第十章中所做的那样，*添加 CRUD 功能*：

```java
// Login.js  
constructor(props) {
  super(props);
  this.state = {username: '', password: '', 
  isAuthenticated: false, open: false};
}
```

我们还需要一个状态处理程序来关闭`Snackbar`的`open`状态，以在`Snackbar`的`autoHideDuration`属性中设置的时间后关闭`Snackbar`：

```java
handleClose = (event) => {
  this.setState({ open: false });
}
```

1.  将`Snackbar`添加到`render()`方法中：

```java
<Snackbar 
  open={this.state.open} onClose={this.handleClose} 
  autoHideDuration={1500} 
  message='Check your username and password' />
```

1.  如果身份验证失败，请将`open`状态值设置为`true`：

```java
login = () => {
  const user = {username: this.state.username, 
      password: this.state.password};
  fetch('http://localhost:8080/login', {
    method: 'POST',
    body: JSON.stringify(user)
  })
  .then(res => {
    const jwtToken = res.headers.get('Authorization');
    if (jwtToken !== null) {
      sessionStorage.setItem("jwt", jwtToken);
      this.setState({isAuthenticated: true});
    }
    else {
      this.setState({open: true});
    }
  })
  .catch(err => console.error(err)) 
}
```

如果您现在使用错误的凭据登录，您可以看到提示消息：

！[](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/33d4ed39-e0a1-483e-8b19-695b009cfe9f.png)

注销功能要实现起来简单得多。您基本上只需从会话存储中删除令牌，并将`isAuthenticated`状态值更改为`false`，如下面的源代码所示：

```java
logout = () => {
    sessionStorage.removeItem("jwt");
    this.setState({isAuthenticated: false});
}
```

然后通过条件渲染，您可以渲染`Login`组件而不是`Carlist`。

如果要使用 React Router 实现菜单，可以实现所谓的安全路由，只有在用户经过身份验证时才能访问。以下源代码显示了安全路由，如果用户经过身份验证，则显示路由组件，否则将重定向到登录页面：

```java
const SecuredRoute = ({ component: Component, ...rest, isAuthenticated }) => (
  <Route {...rest} render={props => (
    isAuthenticated ? (
      <Component {...props}/>
    ) : (
      <Redirect to={{
        pathname: '/login',
        state: { from: props.location }
      }}/>
    )
  )}/>
)
```

这是使用在前面示例中定义的`SecuredRoute`的`Switch`路由的示例。`Login`和`Contact`组件可以在没有身份验证的情况下访问，但`Shop`需要身份验证：

```java
 <Switch>
    <Route path="/login" component={Login} />
    <Route path="/contact" component={Contact} />
    <SecuredRoute isAuthenticated={this.state.isAuthenticated} 
      path="/shop" component={Shop} />
    <Route render={() => <h1>Page not found</h1>} />
  </Switch>
```

# 摘要

在本章中，我们学习了如何在使用 JWT 身份验证时为我们的前端实现登录功能。成功身份验证后，我们使用会话存储保存从后端收到的令牌。然后在发送到后端的所有请求中使用该令牌，因此，我们必须修改我们的 CRUD 功能以正确使用身份验证。在下一章中，我们将部署我们的应用程序到 Heroku，并演示如何创建 Docker 容器。

# 问题

1.  您应该如何创建登录表单？

1.  您应该如何使用 JWT 登录到后端？

1.  您应该如何将令牌存储到会话存储中？

1.  您应该如何在 CRUD 功能中将令牌发送到后端？

# 进一步阅读

Packt 还有其他很好的资源可供学习 React：

+   [`www.packtpub.com/web-development/react-16-tooling`](https://www.packtpub.com/web-development/react-16-tooling)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)


# 第十四章：部署您的应用程序

本章将解释如何将后端和前端部署到服务器。有各种云服务器或 PaaS（平台即服务）提供商可用，如 Amazon（AWS）、DigitalOcean 和 Microsoft Azure。在本书中，我们使用 Heroku，它支持 Web 开发中使用的多种编程语言。我们还将向您展示如何在部署中使用 Docker 容器。

在这一章中，我们将看到以下内容：

+   部署 Spring Boot 应用程序的不同选项

+   如何将 Spring Boot 应用程序部署到 Heroku

+   如何将 React 应用程序部署到 Heroku

+   如何创建 Spring Boot 和 MariaDB Docker 容器

# 技术要求

我们在第四章中创建的 Spring Boot 应用程序，*Securing and Testing Your Backend*，是必需的（GitHub：[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%204`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%204)）。

我们在上一章中使用的 React 应用程序也是必需的（GitHub：[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%2011`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React/tree/master/Chapter%2011)）。

Docker 安装是必要的。

# 部署后端

如果您要使用自己的服务器，部署 Spring Boot 应用程序的最简单方法是使用可执行的 JAR 文件。如果您使用 Maven，可以在命令行中键入`mvn clean install`命令来生成可执行的 JAR 文件。该命令会在`build`文件夹中创建 JAR 文件。在这种情况下，您不必安装单独的应用程序服务器，因为它嵌入在 JAR 文件中。然后，您只需使用`java`命令运行 JAR 文件，`java -jar your_appfile.jar`。嵌入式 Tomcat 版本可以在`pom.xml`文件中使用以下行进行定义：

```java
<properties>
  <tomcat.version>8.0.52</tomcat.version>
</properties>
```

如果您使用单独的应用程序服务器，您必须创建一个 WAR 包。这有点复杂，您必须对应用程序进行一些修改。以下是创建 WAR 文件的步骤：

1.  通过扩展`SpringBootServletIntializer`并重写`configure`方法修改应用程序主类：

```java
@SpringBootApplication
public class Application extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure
        (SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(Application.class, args);
    }
}
```

1.  在`pom.xml`文件中将打包从 JAR 更改为 WAR：

```java
<packaging>war</packaging>
```

1.  将以下依赖项添加到`pom.xml`文件中。然后，Tomcat 应用程序将不再是嵌入式的：

```java
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-tomcat</artifactId>
  <scope>provided</scope>
</dependency>
```

现在，当您构建应用程序时，将生成 WAR 文件。它可以通过将文件复制到 Tomcat 的`/webapps`文件夹来部署到现有的 Tomcat。

现在，云服务器是向最终用户提供应用程序的主要方式。接下来，我们将把后端部署到 Heroku 云服务器（[`www.heroku.com/`](https://www.heroku.com/)）。Heroku 提供免费账户，您可以用来部署自己的应用程序。使用免费账户，应用程序在 30 分钟不活动后会休眠，并且重新启动应用程序需要一点时间。但是免费账户足够用于测试和爱好目的。

对于部署，您可以使用 Heroku 的基于 Web 的用户界面。以下步骤介绍了部署过程：

1.  在你创建了 Heroku 账户之后，登录 Heroku 网站。导航到显示应用程序列表的仪表板。有一个名为“New”的按钮，打开一个菜单。从菜单中选择“Create new app”：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a6d4ea22-fcf1-4db9-87dd-809aee5975e6.png)

1.  为您的应用命名，选择一个区域，并按“Create app”按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a149f89b-24ef-44e8-aa3e-d84df8e12c1e.png)

1.  选择部署方法。有几种选项；我们使用 GitHub 选项。在该方法中，您首先必须将应用程序推送到 GitHub，然后将 GitHub 存储库链接到 Heroku：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/dfe74268-512d-47d2-820e-2b0c4e71dcd4.png)

1.  搜索要部署到的存储库，然后按“连接”按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7b165d48-afdd-475c-b80e-c541060f3089.png)

1.  选择自动部署和手动部署之间。自动选项在您将新版本推送到连接的 GitHub 存储库时自动部署您的应用程序。您还必须选择要部署的分支。我们现在将使用手动选项，在您按下“部署分支”按钮时部署应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/bb891230-f8f6-49cf-bfb7-c25a8c010213.png)

1.  部署开始，您可以看到构建日志。您应该看到一条消息，说您的应用程序已成功部署：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7e706d00-ec4a-48bd-be9f-f7cef58af9c5.png)

现在，您的应用程序已部署到 Heroku 云服务器。如果您使用 H2 内存数据库，这就足够了，您的应用程序应该可以工作。我们正在使用 MariaDB；因此，我们必须安装数据库。

在 Heroku 中，我们可以使用 JawsDB，它作为附加组件在 Heroku 中可用。JawsDB 是一个**Database as a Service** (**DBaaS**)提供商，提供 MariaDB 数据库，可以在 Heroku 中使用。以下步骤描述了如何开始使用数据库：

1.  在 Heroku 应用程序页面的资源选项卡中键入`JawsDB`到附加组件搜索字段中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/4ad75340-c8c9-47b2-b6f4-10c3be62c991.png)

1.  从下拉列表中选择 JawsDB Maria。您可以在附加组件列表中看到 JawsDB。点击 JawsDB，您可以看到数据库的连接信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c9a31fdb-7bc5-4e8b-987f-5bf9c9cad006.png)

1.  在`application.properties`文件中更改数据库连接定义，使用 JawsDB 连接信息页面上的值。在这个例子中，我们使用明文密码，但建议使用例如**Java Simplified Encryption** (**JASYPT**)库来加密密码：

```java
spring.datasource.url=jdbc:mariadb://n7qmaptgs6baip9z.chr7pe7iynqr.eu-west-1.rds.amazonaws.com:3306/ebp6gq2544v5gcpc
spring.datasource.username=bdcpogfxxxxxxx
spring.datasource.password=ke68n28xxxxxxx
spring.datasource.driver-class-name=org.mariadb.jdbc.Driver
```

1.  使用免费帐户，我们可以最多同时有 10 个连接到我们的数据库；因此，我们还必须将以下行添加到`application.properties`文件中：

```java
spring.datasource.max-active=10
```

1.  将更改推送到 GitHub 并在 Heroku 中部署您的应用程序。现在，您的应用程序已准备就绪，我们可以用 Postman 进行测试。应用程序的 URL 是`https://carbackend.herokuapp.com/`，但您也可以使用您自己的域名。如果我们向`/login`端点发送`POST`请求并附带凭据，我们可以在响应头中获得令牌。所以，一切似乎都正常工作：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/118749ea-0281-4a31-998b-ec964fffbac8.png)

您还可以使用 HeidiSQL 连接到 JawsDB 数据库，我们可以看到我们的 car 数据库已经创建：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/1249d3d7-581b-4bca-b51d-5985cc9de735.png)

您可以通过从“更多”菜单中选择“查看日志”来查看应用程序日志：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/bd9588eb-733b-49d1-9680-1bb8943220f6.png)

应用程序日志视图如下所示。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/363c4ce1-f69f-470c-ba27-6d799636bcfa.png)

# 部署前端

在本节中，我们将把 React 前端部署到 Heroku。将 React 应用程序部署到 Heroku 的最简单方法是使用 Heroku Buildpack for create-react-app ([`github.com/mars/create-react-app-buildpack`](https://github.com/mars/create-react-app-buildpack))。为了部署，我们必须安装 Heroku CLI，这是 Heroku 的命令行工具。您可以从`https://devcenter.heroku.com/articles/heroku-cli`下载安装包。安装完成后，您可以从 PowerShell 或您正在使用的终端使用 Heroku CLI。以下步骤描述了部署过程：

1.  使用 VS Code 打开您的前端项目，并在编辑器中打开`constant.js`文件。将`SERVER_URL`常量更改为匹配我们后端的 URL，并保存更改：

```java
export const SERVER_URL = 'https://carbackend.herokuapp.com/'
```

1.  为您的项目创建一个本地 Git 存储库并提交文件，如果您还没有这样做。使用 Git 命令行工具导航到您的项目文件夹，并键入以下命令：

```java
git init
git add .
git commit -m "Heroku deployment"
```

1.  以下命令创建一个新的 Heroku 应用程序，并要求输入 Heroku 的凭据。将`[APPNAME]`替换为您自己的应用程序名称。命令执行后，您应该在 Heroku 仪表板中看到新的应用程序：

```java
heroku create [APPNAME] --buildpack https://github.com/mars/create-react-app-buildpack.git
```

1.  通过在 PowerShell 中输入以下命令将您的代码部署到 Heroku：

```java
git push heroku master
```

部署准备就绪后，您应该在 PowerShell 中看到“验证部署...完成”消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d390c43a-34b7-472f-ba2f-81edd960b837.png)

现在，您可以转到 Heroku 仪表板并查看前端的 URL；您还可以通过在 Heroku CLI 中输入`heroku open`命令来打开它。如果导航到前端，您应该看到登录表单：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/0dd6d124-54bd-46c9-8dec-8cc247c37495.png)

# 使用 Docker 容器

Docker 是一个容器平台，使软件开发、部署和交付更加简单。容器是轻量级和可执行的软件包，包括运行软件所需的一切。在本节中，我们正在从 Spring Boot 后端创建一个容器，如下所示：

1.  将 Docker 安装到您的工作站。您可以在[`www.docker.com/get-docker`](https://www.docker.com/get-docker)找到安装包。有多个平台的安装包，如果您使用 Windows 操作系统，可以使用默认设置通过安装向导进行安装。

1.  Spring Boot 应用程序只是一个可执行的 JAR 文件，可以使用 Java 执行。可以使用以下 Maven 命令创建 JAR 文件：

```java
mvn clean install
```

您还可以使用 Eclipse 通过打开“Run | Run configurations...”菜单来运行 Maven 目标。在“Base directory”字段中选择您的项目，使用“Workspace”按钮。在“Goals”字段中输入 clean install 并按“Run”按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/787f9e0c-1e26-4665-a2fb-7e45e7e50913.png)

1.  构建完成后，您可以从`/target`文件夹中找到可执行的 JAR 文件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/2492af3f-cc3b-41c8-b4f0-8229438a3b18.png)

1.  您可以通过以下命令运行 JAR 文件来测试构建是否正确：

```java
 java -jar .\cardatabase-0.0.1-SNAPSHOT.jar
```

1.  您将看到应用程序的启动消息，最后，您的应用程序正在运行：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/14a5ad6d-15a2-4e4f-8fdb-f4e0b78be6bd.png)

容器是通过使用 Dockerfile 定义的。

1.  在项目的根文件夹中创建一个名为`Dockerfile`的新 Dockerfile。以下行显示了 Dockerfile 的内容。我们使用 Alpine Linux。`EXPOSE`定义应在容器外发布的端口。`COPY`将 JAR 文件复制到容器的文件系统并将其重命名为`app.jar`。`ENTRYPOINT`定义 Docker 容器运行的命令行参数。

还有一个 Maven 插件可用于构建 Docker 镜像。它由 Spotify 开发，可以在[`github.com/spotify/docker-maven-plugin`](https://github.com/spotify/docker-maven-plugin)找到。

以下行显示了`Dockerfile`的内容。

```java
FROM openjdk:8-jdk-alpine
VOLUME /tmp
EXPOSE 8080
ARG JAR_FILE
COPY target/cardatabase-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
```

1.  使用以下命令创建容器。使用`-t`参数，我们可以为容器指定一个友好的名称：

```java
docker build -t carbackend .
```

在构建命令结束时，您应该看到“成功构建”消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d14a98c9-6013-4f50-a078-d0261a7ac6fe.png)

1.  使用`docker image ls`命令检查容器列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a711dc13-1ae6-4f6e-906d-3aea1272fbae.png)

1.  使用以下命令运行容器：

```java
docker run -p 4000:8080 carbackend
```

Spring Boot 应用程序启动，但以错误结束，因为我们正在尝试访问本地主机数据库。现在本地主机指向容器本身，并且没有安装 MariaDB。

1.  我们将为 MariaDB 创建自己的容器。您可以使用以下命令从 Docker Hub 拉取最新的 MariaDB 容器：

```java
docker pull mariadb:lates
```

1.  运行 MariaDB 容器。以下命令设置 root 用户密码并创建一个新的名为`cardb`的数据库，这是我们 Spring Boot 应用程序所需的：

```java
docker run --name cardb -e MYSQL_ROOT_PASSWORD=pwd -e MYSQL_DATABASE=cardb mariadb
```

1.  我们必须对 Spring Boot 的`application.properties`文件进行一些更改。将`datasource`的 URL 更改为以下内容。在下一步中，我们将指定我们的应用可以使用`mariadb`名称访问数据库容器。更改后，您必须构建您的应用程序并重新创建 Spring Boot 容器：

```java
spring.datasource.url=jdbc:mariadb://mariadb:3306/cardb
```

1.  我们可以运行我们的 Spring Boot 容器，并使用以下命令将 MariaDB 容器链接到它。该命令现在定义了我们的 Spring Boot 容器可以使用`mariadb`名称访问 MariaDB 容器：

```java
docker run -p 8080:8080 --name carapp --link cardb:mariadb -d carbackend
```

1.  我们还可以通过输入`docker logs carapp`命令来访问我们的应用程序日志。我们可以看到我们的应用程序已成功启动，并且演示数据已插入到存在于 MariaDB 容器中的数据库中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/2e83d7a2-9eb6-4f6c-9948-ed2f9e288e01.png)

# 摘要

在本章中，我们学习了如何部署 Spring Boot 应用程序。我们了解了 Spring Boot 应用程序的不同部署选项，并将应用程序部署到了 Heroku。接下来，我们使用 Heroku Buildpack for create-react-app 将 React 前端部署到了 Heroku，这使得部署过程更快。最后，我们使用 Docker 从 Spring Boot 应用程序和 MariaDB 数据库创建了容器。在下一章中，我们将介绍一些您应该探索的更多技术和最佳实践。

# 问题

1.  你应该如何创建一个 Spring Boot 可执行的 JAR 文件？

1.  你应该如何将 Spring Boot 应用部署到 Heroku？

1.  你应该如何将 React 应用部署到 Heroku？

1.  什么是 Docker？

1.  你应该如何创建 Spring Boot 应用容器？

1.  你应该如何创建 MariaDB 容器？

# 进一步阅读

Packt 还有其他很好的资源，可以学习关于 React，Spring Boot 和 Docker 的知识：

+   [`www.packtpub.com/web-development/react-16-tooling`](https://www.packtpub.com/web-development/react-16-tooling)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)

+   [`www.packtpub.com/virtualization-and-cloud/deployment-docker`](https://www.packtpub.com/virtualization-and-cloud/deployment-docker)

+   [`www.packtpub.com/virtualization-and-cloud/docker-fundamentals-integrated-course`](https://www.packtpub.com/virtualization-and-cloud/docker-fundamentals-integrated-course)
