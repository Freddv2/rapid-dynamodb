package com.github.freddv2.dynamodb;

public class RapidDynamoDBClientException extends RuntimeException {

    public RapidDynamoDBClientException(String message) {
        super(message);
    }

    public RapidDynamoDBClientException(Throwable cause) {
        super(cause);
    }
}
