package cn.metaq.oauth2.server.common.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.Serializable;

/**
 * Restful接口响应结果封装
 *
 * @author : 1191
 * @version 1.0
 * @date: 2020-02-06 10:20
 */
public class Result<T> implements Serializable {


  private Integer statusCode;

  private String message;

  @JsonInclude(JsonInclude.Include.NON_NULL)
  private T data;

  public static <T> Result<T> ok(T data) {
    return new Result<T>().data(data).statusCode(200).message("OK");
  }

  public static <T> Result<T> ok() {
    return new Result<T>().statusCode(200).message("OK");
  }

  public static <T> Result<T> error() {
    return error(500, "Internal Server Error");
  }

  public static <T> Result<T> error(String msg) {
    return error(500, msg);
  }

  public static <T> Result<T> error(Integer statusCode, String message) {
    return new Result<T>().statusCode(statusCode).message(message);
  }

  public static <T> Result<T> ok(T data, String message) {
    return new Result<T>().data(data).statusCode(200).message(message);
  }

  private Result<T> data(T data) {
    this.data = data;
    return this;
  }

  private Result<T> statusCode(Integer statusCode) {
    this.statusCode = statusCode;
    return this;
  }

  private Result<T> message(String message) {
    this.message = message;
    return this;
  }

  public Integer getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(Integer statusCode) {
    this.statusCode = statusCode;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  public T getData() {
    return data;
  }

  public void setData(T data) {
    this.data = data;
  }
}