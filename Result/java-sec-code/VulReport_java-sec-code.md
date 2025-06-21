# JavaSinkTracer扫描报告
- 报告时间：2025-06-21 22:42:36
- 项目名称：**java-sec-code**
- 源码路径：D:/Code/Github/java-sec-code
- 污点数量：共存在 **10** 条污点链路

# RCE漏洞(1个)

本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'Runtime:exec'** 的调用链。

## 污点链路1

**1）漏洞基础信息**

- 漏洞简述: 任意代码执行漏洞

- 严重等级: **High**

- Sink函数: **Runtime:exec**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:CommandExec

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:CommandExec
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            Process p = run.exec(cmd);
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "Command exec failed!!";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            return e.toString();
        }
        return sb.toString();
    }


```


# RCE漏洞(1个)

本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'GroovyShell:evaluate'** 的调用链。

## 污点链路2

**1）漏洞基础信息**

- 漏洞简述: 任意代码执行漏洞

- 严重等级: **High**

- Sink函数: **GroovyShell:evaluate**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:groovyshell

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:groovyshell
    public void groovyshell(String content) {
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(content);
    }


```


# UNSERIALIZE漏洞(1个)

本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'ObjectInputStream:readObject'** 的调用链。

## 污点链路3

**1）漏洞基础信息**

- 漏洞简述: 反序列化漏洞

- 严重等级: **High**

- Sink函数: **ObjectInputStream:readObject**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Shiro.java:shiro_deserialize

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Shiro.java:shiro_deserialize
    public String shiro_deserialize(HttpServletRequest req, HttpServletResponse res) {
        Cookie cookie = getCookie(req, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        try {
            String rememberMe = cookie.getValue();
            byte[] b64DecodeRememberMe = java.util.Base64.getDecoder().decode(rememberMe);
            byte[] aesDecrypt = acs.decrypt(b64DecodeRememberMe, KEYS).getBytes();
            ByteArrayInputStream bytes = new ByteArrayInputStream(aesDecrypt);
            ObjectInputStream in = new ObjectInputStream(bytes);
            in.readObject();
            in.close();
        } catch (Exception e){
            if (CookieUtils.addCookie(res, "rememberMe", DELETE_ME)){
                log.error(e.getMessage());
                return "RememberMe cookie decrypt error. Set deleteMe cookie success.";
            }
        }

        return "Shiro deserialize";
    }


```


# UNSERIALIZE漏洞(2个)

本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'Yaml:load'** 的调用链。

## 污点链路4

**1）漏洞基础信息**

- 漏洞简述: 反序列化漏洞

- 严重等级: **High**

- Sink函数: **Yaml:load**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:yarm

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:yarm
    public void yarm(String content) {
        Yaml y = new Yaml();
        y.load(content);
    }


```

## 污点链路5

**1）漏洞基础信息**

- 漏洞简述: 反序列化漏洞

- 严重等级: **High**

- Sink函数: **Yaml:load**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:secYarm

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\Rce.java:secYarm
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }


```


# SSRF漏洞(4个)

本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'URL:openConnection'** 的调用链。

## 污点链路6

**1）漏洞基础信息**

- 漏洞简述: 服务端请求伪造漏洞

- 严重等级: **Medium**

- Sink函数: **URL:openConnection**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:URLConnectionVuln
- D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:URLConnection

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:URLConnectionVuln
    public String URLConnectionVuln(String url) {
        return HttpUtils.URLConnection(url);
    }


// D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:URLConnection
    public static String URLConnection(String url) {
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


```

## 污点链路7

**1）漏洞基础信息**

- 漏洞简述: 服务端请求伪造漏洞

- 严重等级: **Medium**

- Sink函数: **URL:openConnection**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:URLConnectionSec
- D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:URLConnection

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:URLConnectionSec
    public String URLConnectionSec(String url) {

        // Decline not http/https protocol
        if (!SecurityUtil.isHttp(url)) {
            return "[-] SSRF check failed";
        }

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.URLConnection(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


// D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:URLConnection
    public static String URLConnection(String url) {
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


```

## 污点链路8

**1）漏洞基础信息**

- 漏洞简述: 服务端请求伪造漏洞

- 严重等级: **Medium**

- Sink函数: **URL:openConnection**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:httpURLConnection
- D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:HttpURLConnection

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:httpURLConnection
    public String httpURLConnection(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.HttpURLConnection(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


// D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:HttpURLConnection
    public static String HttpURLConnection(String url) {
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            HttpURLConnection conn = (HttpURLConnection) urlConnection;
//             conn.setInstanceFollowRedirects(false);
//             Many HttpURLConnection methods can send http request, such as getResponseCode, getHeaderField
            InputStream is = conn.getInputStream();  // send request
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (IOException e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


```

## 污点链路9

**1）漏洞基础信息**

- 漏洞简述: 服务端请求伪造漏洞

- 严重等级: **Medium**

- Sink函数: **URL:openConnection**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:httpURLConnectionVuln
- D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:HttpURLConnection

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:httpURLConnectionVuln
    public String httpURLConnectionVuln(@RequestParam String url) {
        return HttpUtils.HttpURLConnection(url);
    }


// D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:HttpURLConnection
    public static String HttpURLConnection(String url) {
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            HttpURLConnection conn = (HttpURLConnection) urlConnection;
//             conn.setInstanceFollowRedirects(false);
//             Many HttpURLConnection methods can send http request, such as getResponseCode, getHeaderField
            InputStream is = conn.getInputStream();  // send request
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (IOException e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


```


# SSRF漏洞(1个)

本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'OkHttpClient:newCall'** 的调用链。

## 污点链路10

**1）漏洞基础信息**

- 漏洞简述: 服务端请求伪造漏洞

- 严重等级: **Medium**

- Sink函数: **OkHttpClient:newCall**

**2）调用链路信息**

- D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:okhttp
- D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:okhttp

**3）链路完整代码**

```java
// D:/Code/Github/java-sec-code\src\main\java\org\joychou\controller\SSRF.java:okhttp
    public String okhttp(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.okhttp(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


// D:/Code/Github/java-sec-code\src\main\java\org\joychou\util\HttpUtils.java:okhttp
    public static String okhttp(String url) throws IOException {
        OkHttpClient client = new OkHttpClient();
//         client.setFollowRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(url).build();
        return client.newCall(ok_http).execute().body().string();
    }


```


