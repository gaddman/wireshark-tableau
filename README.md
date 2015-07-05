# wireshark-tableau
A Wireshark LUA script to export specified packet information to a CSV file for use in Tableau

Tap to export capture to a suitable file for [Tableau](http://www.tableau.com) to read. File is just a CSV of interesting packets in an appropriate format, to suit a prepared Tableau workbook.

Strings are double-quoted. Data lines have a trailing comma, because I'm lazy,
