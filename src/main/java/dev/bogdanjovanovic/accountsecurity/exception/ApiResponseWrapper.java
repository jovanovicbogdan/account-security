package dev.bogdanjovanovic.accountsecurity.exception;

public class ApiResponseWrapper<T> {

  private T data;

  public ApiResponseWrapper() { }

  public ApiResponseWrapper(final T data) {
    this.data = data;
  }

  public T getData() {
    return data;
  }

  public void setData(T data) {
    this.data = data;
  }
}
