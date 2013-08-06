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

    var pathname = window.location.pathname;
    var checkpath=pathname.split("/").length;
    var uri =  'libraryHierarchy';
    if(checkpath<2)
    {
        uri =  'libraryHierarchy';
    }
    else
    {
        uri =  '../../libraryHierarchy';
    }

    document.getElementById('serapplib').options.length = 0;
    document.getElementById('serapplibver').options.length = 0;
    $.ajax({ // ajax call starts
        url: uri, // JQuery loads serverside.php
        dataType: 'json', // Choosing a JSON datatype
        success: function(data) // Variable data contains the data we get from serverside
        {
            $('<option/>').val(" ").html("--").appendTo('#serapplib');
            $('<option/>').val(" ").html("--").appendTo('#serapplibver');
            var vendjs,libjs,verjs;
              for(var i=0;i<data.vendors.length;i++)
              {

                     vendjs=data.vendors[i];
                  for(var j=0;j<vendjs.libraries.length;j++)
                  {

                      libjs=vendjs.libraries[j];
                      $('<option/>').val(libjs.libid).html(libjs.libname).appendTo('#serapplib');
                      for(var k=0;k<libjs.versions.length;k++)
                      {
                          verjs=libjs.versions[k];
                          $('<option/>').val(verjs. libverid).html(verjs.libver).appendTo('#serapplibver');
                      }

                  }
              }

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

 function populatetextbox(id,str)
 {
     var value = str.options[str.selectedIndex].value;
     $(id).val(value);
 }