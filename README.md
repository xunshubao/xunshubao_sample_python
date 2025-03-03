执行公开接口使用规范说明（V3.0）

# 基本约定
## 基本数据类型
在对数据项进行描述时，本规范定义了11种基本数据类型。在用JSON描述数据项时，各数据项的取值本质上都是以字符串的形式表述。
| 数据类型 | 定义 | JSON文本格式 |
|--- | --- | --- |
| N |	数字字符串，Unicode 字符集范围为\u0030-\u0039 |	数字字符串 |
| AN | 数字字符和英文字符组成的字符串，Unicode字符集范围为\u0020-\u007E |	数字字符和英文字符组成的字符串 |
| ANC |	可以包含所有字符 (包括汉字) 的字符串 |	可以包含所有字符 (包括汉字) 的字符串 |
| Enum | 枚举(代码) 型数据。代码可以由数字和英文字母构成 | 数字和英文字母构成的字符串，总长度不超过 8 |
| Year | 年份 |	由数字字符组成的用以表示日期的字符串 (格式 yyyy) |
| Month | 年月 (包含年、月) |	由数字字符组成的用以表示日期的字符串 (格式为 yyyyMM) 例: 202102 |
| Date | 日期 (包含年、月、日) |	由数字字符组成的用以表示日期的字符串 (格式为 yyyyMMdd) 例: 20210201 |
| Time |	时间 (包含年、月、日、时、分、秒) |	由数字字符组成的用以表示时间的字符串 (格式为 yyyyMMddHHmmss) 例: 20220908220200|
| Timestamp |	时间戳，精确到毫秒	|  |
| Int |	整数 | 由数字字符和“-”组成的十进制整数的字符串其中“-”加在数字前表示该整数位负数|
| Float |	实数 | 由数字字符、“-”“.”组成的十进制实数的字符串，其中“.”用以分隔整数和小数部分、8加在数字前表示该实数是负数|

## 复合数据类型
在对数据对象进行描述时，本规范定义了 2 种复合数据类型。
| 数据类型 |	定义 |
| --- | --- |
|Object |	对象类型，由基本数据类型和复合数据类型组合而成|
|Array |	数组类型，具有相同基本数据类型或复合数据类型的有序集|

## 填写约定
本规范从两个维度对数据项和数据对象的填写进行约束：一是出现约束，规定是否出现；二是空值约束，规定当出现时，取值是否允许为空。
- 针对数据项或数据对象是否需要出现，本规范做了如下定义：\
  所有的数据项或者数据对象都要出现，父数据对象是空值的情况除外。
- 针对数据项或数据对象是否可以填写空值，本规范使用了3 种类型的填写约束：
1. M（非空型），表示必须填写有意义的值，不能填写空值。
2. O（可空型），当此数据项或数据对象获取不到相关信息时，可以填写空值。
3. C（条件非空），在特定条件为真的情况下，必须填报有意义的值，不能填写空值；反之，可以为空值。

## 空值约定
在基本数据类型中，如果 Int 或者 Float 类型为空值，填写 null；其它情况，填写空字符串（“”）。
在复合数据类型中如果 Array 类型为空值，填写[]；如果 Object 类型为空值，填写null。

## 信息交换编码约定
在信息交换时采用“Unicode”字符集以及 UTF-8 编码。

## 网络传输协议
对于单笔接口，使用HTTP/HTTPS 传输协议，具体约定如下表 所示：
| 序号 |	约定项 |	约定描述|
| --- | --- | --- |
| 1 |	通讯协议|	HTTP/HTTPS 协议。|
| 2 |	TLS 版本|	TLSv1.2|
| 3 |	HTTP METHOD |	GET/POST|
| 4 |	HTTP STATUS |	200 表示网络传输成功，其它表示不成功。|
| 5 |	响应Content-Type |	application/json|
| 6 |	报文格式 |	JSON|

## 签名
数字签名是把用户标识（appKey）、请求时间戳（timestamp）、签名密钥（signSecretKey）、请求参数（requestBody）进行拼接，然后使用摘要算法进行加密得到签名值。
摘要算法默认使用SM3，可选择使用MD5和SHA256。
可逆解密支持SM4和AES，分别使用sm4SecretKey和aesSecretKey密钥。

## 公共请求参数
### 请求头信息（requestHeader）
|数据项 |	名称 |	类型 |	空值约束 |	示例/备注|
| --- | --- | --- | --- | --- |
|appKey |	用户标识 |	AN |	M	 |
|timestamp |	时间戳 |	Timestamp | M |	当前时间的时间戳（毫秒）|
|signType |	摘要算法 |	AN..6 |	O |	默认SM3，支持MD5/SHA256|
|token |	签名 |	AN64 |	M | 	例：SM3（appKey+timestamp+secretKey+requestBody）|
|requestId |	请求标识 |	AN..64 |	O	| 请求唯一标识，一个appKey下全局唯一|
|encryption |	加密方式 |	AN..6	| O |	对请求参数和返回内容加密 默认SM4，支持AES|

### 请求参数示例
```json
{
    "requestHeader":{
        "appKey": "用户标识",
        "timestamp": "1721898937532",
        "token": "签名",
        "signType": "MD5",
        "requestId": "202407011400220001",
        "encryption": "SM4"
    },
    "requestBody":"加密后的请求参数"
}
```

## 返回结果参数
|数据项 |	名称 |	类型 |	空值约束 |	示例/备注|
| --- | --- | --- | --- | --- |
|code|	结果代码|	AN |	M	 |0000代表成功，其余为失败，详见附录A|
|msg|	结果消息|	ANC |	M |	错误消息提示|
|requestId|	请求标识 |	AN..64 |	M |	如用户请求时未提交该参数，则返回自动生成的UUID|
|data|	结果数据 |	Object |	O |	具体类型以业务接口说明为准。|

```json
{
    "code": "0000",
    "msg": "",
    "requestId": "202407011400220001",
    "data": "加密后的返回数据"
}
```


