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

    $(document).ready(function() {
    $("table.tablesorter").tablesorter();
    $("#adddeplibrary").chainedTo("#adddepvendor");
    $("#adddepversion").chainedTo("#adddeplibrary");
});


$(document).on("click",".open-SearchApplicationModal", function (){


    $.ajax({ // ajax call starts
        url: 'libraryHierarchy', // JQuery loads serverside.php
        dataType: 'json', // Choosing a JSON datatype
        success: function(data) // Variable data contains the data we get from serverside
        {
         /*   $("#serapplib").empty();*/
     /*       $.each(data, function () {
                $("#serapplib").append($("<option />").val(this.vendors[0].libraries[0].libid).text(this.vendors[0].libraries[0]. libname));
            });*/
           // alert(data.vendors.length);

            for (var i=0;i<data.vendors.length;i++){
                $('<option/>').val(data.vendors[i].id).html(data.vendors[i].id).appendTo('#serapplibven');
                $('<option/>').val(data.vendors[i].libraries[0].libid).html(data.vendors[i].libraries[0].libname).appendTo('#serapplib');
                $('<option/>').val(data.vendors[i].libraries[0].versions[0]. libverid).html(data.vendors[i].libraries[0].versions[0].libver).appendTo('#serapplibver');

            }

           /* $(".modal-body #serapplib").val(data.vendors[0].libraries[0]. libname );
            $(".modal-body #serapplibver").val(data.vendors[0].libraries[0].versions[0]. libver );
            $(".modal-body #serapplibven").val(data.vendors[0]. vendor );*/
        }

        });
});


$(document).on("click", ".open-EditApplicationModal", function () {
    $("#deleteLink").attr("href", "deleteApplication/" + $(this).data('id') );
    $(".modal-body #editid").val( $(this).data("id") );
    $(".modal-body #editname").val( $(this).data("name") );
});

$(document).on("click", ".open-AddApplicationVersionModal", function () {
    $(".modal-body #addid").val( $(this).data("id") );
});

$(document).on("click", ".open-AddDependencyModal", function () {
    //$(".modal-body #addid").val( $(this).data("id") );
});

/*LIBRARY EDIT OPTION*/

$(document).on("click", ".open-EditLibrariesModal", function () {
    $("#deleteLibrary").attr("href", "removelibrary/" + $(this).data('libraryversionid') );

    $(".modal-body #editvendorid").val( $(this).data("vendorid") );
    $(".modal-body #editlicenseid").val( $(this).data("licenseid") );
    $(".modal-body #editlibraryid").val( $(this).data("libraryid") );
    $(".modal-body #editlibraryversionid").val( $(this).data("libraryversionid") );

    $(".modal-body #librarynameedit").val( $(this).data("libraryname") );
    $(".modal-body #libraryversionedit").val( $(this).data("libraryversion") );
    $(".modal-body #vendoredit").val( $(this).data("vendor") );
    $(".modal-body #licenseedit").val( $(this).data("licensename") );
    $(".modal-body #languageedit").val( $(this).data("language") );
    $(".modal-body #secuniaIDedit").val( $(this).data("secunia") );
});

/*CLONE APPLICATION*/
$(document).on("click", ".open-CloneApplicationModal", function ()
{
    $(".modal-body #applicationid").val( $(this).data("id") );


});

/*CLONE APPLICATION VERSION*/
$(document).on("click", ".open-CloneApplicationVersionModal", function ()
{
    $(".modal-body #applicationid").val( $(this).data("id") );
    $(".modal-body #applicationversion").val( $(this).data("version") );
});




/* LICENSE DISPLAY AND DOWNLOAD*/
$(document).on("click", ".open-LicenseLibrariesModal", function ()
{
   $("#viewlicense").attr("src", "viewlicense/" + $(this).data('licenseid') );


    $(".modal-body #licenseid").val( $(this).data("licenseid") );
    $(".modal-body #licensename").val( $(this).data("licensename") );
    $(".modal-body #licensfileename").val( $(this).data("licensfileename") );

    if (($(this).data("licensefiletype") != "text/plain") ||($(this).data("licensefiletype") != "text/html") ) {
        var frame = document.getElementById("hideviewlicense");
        frame.parentNode.removeChild(frame);

    }

});


/* EDIT APPVERSION*/
$(document).on("click", ".open-EditDependencyModal", function ()
{

    $("#deleteAppVer").attr("href", "../../deleteApplicationVersion/" + $(this).data('id') );
    $(".modal-body #appversionid").val( $(this).data("id") );
    $(".modal-body #editappver").val( $(this).data("ver") );

});