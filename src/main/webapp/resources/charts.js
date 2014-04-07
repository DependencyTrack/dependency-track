/*
 * Copyright 2013 Axway
 *
 * This file is part of OWASP Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Dependency-Track.
 * If not, see http://www.gnu.org/licenses/.
 */

function contextPath() {
    return $.cookie("CONTEXTPATH");
}

google.load("visualization", "1", {packages:["corechart"]});
google.setOnLoadCallback(drawChart);
function drawChart() {


    var dataone = new google.visualization.DataTable();
    dataone.addColumn('string', 'Date');
    dataone.addColumn('number', 'First Release Vulnerabilities');
    dataone.addRows([
        ['11/20/2013', 3],
        ['11/30/2013', 2],

    ]);

    ;
    var datatwo = new google.visualization.DataTable();

    datatwo.addColumn('string', 'Scan');
    datatwo.addColumn('number', 'Vulnerability Count');

    datatwo.addRows([
        ['8/30/2013', 32],
        ['9/30/2013', 31],
        ['10/30/2013', 33],
        ['11/30/2013', 13],
    ]);




    var datathree = new google.visualization.DataTable();
    datathree.addColumn('string', 'Vulnerability Type');
    datathree.addColumn('number', 'Severity');
    datathree.addRows([
        ['Vulv1', 9],
        ['Vulv2', 5],
        ['Vulv3', 6],
        ['Vulv4', 7],

    ]);


    // Set chart options
    var optionsone = {'title':'First Release Vulnerability'
        };
    var optionstwo = {'title':'Number of Vulnerability'
    };
    var optionsthree = {'title':'Severity of vulnerability'
    };


    // Instantiate and draw our chart, passing in some options.
/*
    var chart = new google.visualization.LineChart(document.getElementById('chart_divone'));
    chart.draw(dataone, optionsone);
        chart = new google.visualization.LineChart(document.getElementById('chart_divtwo'));
    chart.draw(datatwo, optionstwo);
    chart = new google.visualization.BarChart(document.getElementById('chart_divthree'));
    chart.draw(datathree, optionsthree);
*/



    /*var chart = new google.visualization.LineChart(document.getElementById('chart_div'));
    chart.draw(newdata, options);*/
}

$(document).on("click", ".visualizeData", function () {

    var versionid = $(this).data('versionid');

    var applicationid=$(this).data("applicationid");


 var uri = contextPath() + '/chartdata/'+versionid;


    var something;
     $.ajax({
     url: uri,
     type: 'GET',
     success: function (data) // Variable data contains the data we get from serverside
     {

         data = $.parseJSON(data);

         var datathree = new google.visualization.DataTable();

         datathree.addColumn('string', 'Vulnerability Type');
         datathree.addColumn('number', 'Severity');
         datathree.addRows(1);
         datathree.setCell(0, 0, data.vuln);
         datathree.setCell(0, 1, parseFloat(data.cvss));


         var optionsthree = {'title':'Severity of vulnerability',
             'width':600,
             'height':300
         };


         var chart = new google.visualization.BarChart(document.getElementById('chart_divthree'));
         chart.draw(datathree, optionsthree);
     },
         error : function(e) {
             alert('Error: ' + e);
         }
     });



    var dataone = new google.visualization.DataTable();
    dataone.addColumn('string', 'Date');
    dataone.addColumn('number', 'First Release Vulnerabilities');
    dataone.addRows([
        ['11/5/2013', 13],
        ['11/10/2013', 9],
        ['11/20/2013', 8],
        ['11/30/2013', 2],

    ]);

    ;
    var datatwo = new google.visualization.DataTable();

    datatwo.addColumn('string', 'Scan');
    datatwo.addColumn('number', 'Vulnerability Count');

    datatwo.addRows([
        ['8/30/2013', 32],
        ['9/30/2013', 31],
        ['10/30/2013', 33],
        ['11/30/2013', 13],
    ]);


    /*var datathree = new google.visualization.DataTable();
    datathree.addColumn('string', 'Vulnerability Type');
    datathree.addColumn('number', 'Severity');
    datathree.addRows([
        ['Vulv1', 9],
        ['Vulv2', 5],
        ['Vulv3', 6],
        ['Vulv4', 7],

    ]);*/


    // Set chart options
    var optionsone = {'title':'First Release Vulnerability',
                        'width':600,
                        'height':300 };
    var optionstwo = {'title':'Number of Vulnerability',
        'width':600,
        'height':300
    };
    var optionsthree = {'title':'Severity of vulnerability',
        'width':600,
        'height':300
    };


    // Instantiate and draw our chart, passing in some options.
    var chart = new google.visualization.LineChart(document.getElementById('chart_divone'));
    chart.draw(dataone, optionsone);
    chart = new google.visualization.LineChart(document.getElementById('chart_divtwo'));
    chart.draw(datatwo, optionstwo);


});