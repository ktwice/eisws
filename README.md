# eisws
EIS SOAP-services tool for Java Platform SE 8.

1. Compile .java to .class:
 javac Eisws.java

2. Start Eisws.class with cmd.xml next:
 java -classpath . Eisws cmd.xml

Запускается с обязательным параметром - имя файла с запросами к сервисам ЕИС УрГЭУ.
Реквизиты доступа берутся из переменных среды eiswsu/eiswsp.
