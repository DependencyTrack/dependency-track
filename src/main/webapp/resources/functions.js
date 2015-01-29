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

$(document).ready(function () {
    $("table.tablesorter").tablesorter();
    $("#adddeplibrary").chainedTo("#adddepvendor");
    $("#adddepversion").chainedTo("#adddeplibrary");
    $(document.getElementById('Licensefile')).hide();
    $(document.getElementById('Licensefilelabel')).hide();
});

$(document).on("click", ".open-SearchApplicationModal", function () {
    var uri = contextPath() + "/libraryHierarchy";

    document.getElementById('serapplib').options.length = 0;
    document.getElementById('serapplibver').options.length = 0;
    document.getElementById('serappven').options.length = 0;
    document.getElementById('coarseSearchVendor').options.length = 0;
    $.ajax({ // ajax call starts
        url: uri, // JQuery loads serverside.php
        dataType: 'json', // Choosing a JSON datatype
        success: function (data) // Variable data contains the data we get from serverside
        {
            $('<option/>').val("").html("--").appendTo('#serappven');
            $('<option/>').addClass("").val("").html("--").appendTo('#serapplib');
            $('<option/>').addClass("").val(-1).html("--").appendTo('#serapplibver');
            $('<option/>').val("").html("--").appendTo('#coarseSearchVendor');
            var vendjs, libjs, verjs;
            for (var i = 0; i < data.vendors.length; i++) {
                vendjs = data.vendors[i];
                $('<option/>').val(vendjs.id).html(vendjs.vendor).appendTo('#serappven');
                $('<option/>').val(vendjs.id).html(vendjs.vendor).appendTo('#coarseSearchVendor');

                for (var j = 0; j < vendjs.libraries.length; j++) {
                    libjs = vendjs.libraries[j];
                    var id = libjs.libid;
                    $('<option/>').addClass(vendjs.id.toString()).val(libjs.libid).html(libjs.libname).appendTo('#serapplib');
                    $('<option/>').addClass(id.toString()).val(-1).html("ALL").appendTo('#serapplibver');

                    for (var k = 0; k < libjs.versions.length; k++) {
                        verjs = libjs.versions[k];

                        $('<option/>').addClass(id.toString()).val(verjs.libverid).html(verjs.libver).appendTo('#serapplibver');

                    }
                }
            }
            $("#serapplib").chainedTo("#serappven");
            $("#serapplibver").chainedTo("#serapplib");
        }


    });
});


$(document).on("click", ".open-EditApplicationModal", function () {
    $("#deleteLink").attr("href", contextPath() + "/deleteApplication/" + $(this).data('id'));
    $(".modal-body #editid").val($(this).data("id"));
    $(".modal-body #editname").val($(this).data("name"));
});

$(document).on("click", ".open-AddApplicationVersionModal", function () {
    $(".modal-body #addid").val($(this).data("id"));
});

$(document).on("click", ".open-AddDependencyModal", function () {
    //$(".modal-body #addid").val( $(this).data("id") );
});

/*LIBRARY EDIT OPTION*/

$(document).on("click", ".open-EditLibrariesModal", function () {
    $("#deleteLibrary").attr("href", contextPath() + "/removelibrary/" + $(this).data('libraryversionid'));

    $(".modal-body #editvendorid").val($(this).data("vendorid"));
    $(".modal-body #editlicenseid").val($(this).data("licenseid"));
    $(".modal-body #editlibraryid").val($(this).data("libraryid"));
    $(".modal-body #editlibraryversionid").val($(this).data("libraryversionid"));

    $(".modal-body #librarynameedit").val($(this).data("libraryname"));
    $(".modal-body #libraryversionedit").val($(this).data("libraryversion"));
    $(".modal-body #vendoredit").val($(this).data("vendor"));
    $(".modal-body #licenseedit").val($(this).data("licensename"));
    $(".modal-body #languageedit").val($(this).data("language"));
});

/*CLONE APPLICATION*/
$(document).on("click", ".open-CloneApplicationModal", function () {
    $(".modal-body #applicationid").val($(this).data("id"));


});

/*CLONE APPLICATION VERSION*/
$(document).on("click", ".open-CloneApplicationVersionModal", function () {
    $(".modal-body #applicationid").val($(this).data("id"));
    $(".modal-body #applicationversion").val($(this).data("version"));
});


/* LICENSE DISPLAY AND DOWNLOAD*/
$(document).on("click", ".open-LicenseLibrariesModal", function () {
    $("#viewlicense").attr("src", contextPath() + "/viewlicense/" + $(this).data('licenseid'));

    $(".modal-body #licenseid").val($(this).data("licenseid"));
    $(".modal-body #licensename").val($(this).data("licensename"));
    $(".modal-body #licensfileename").val($(this).data("licensfileename"));


    if (($(this).data("licensefiletype") != "text/plain") || ($(this).data("licensefiletype") != "text/html")) {
        var frame = document.getElementById("hideviewlicense");
        frame.parentNode.removeChild(frame);
    }
});

$(document).on("click", ".open-licenseFileUploadModalButton", function () {
    var id = $(".modal-body #licenseid").val();
    //var id = $("#licenseLibrariesModal .modal-body #licenseid").va;
    $(".modal-body #uploadlicenseid").val(id);
    var licensename=$(".modal-body #licensename").val();
    $(".modal-body #editlicensename").val(licensename);

});


/* EDIT APPVERSION*/
$(document).on("click", ".open-EditDependencyModal", function () {
    $("#deleteAppVer").attr("href", contextPath() + "/deleteApplicationVersion/" + $(this).data('id'));
    $(".modal-body #appversionid").val($(this).data("id"));
    $(".modal-body #editappver").val($(this).data("ver"));

});

function populatetextbox(id, str) {
    var value = str.options[str.selectedIndex].value;
    $(id).val(value);
}

$(document).on("click", ".open-AddLibraryModal", function () {

    document.getElementById('vendorid').options.length = 0;
    document.getElementById('librarynameid').options.length = 0;
    document.getElementById('libraryversionid').options.length = 0;
    $.ajax({ // ajax call starts
        url: contextPath() + '/libraryHierarchy', // JQuery loads serverside.php
        dataType: 'json', // Choosing a JSON datatype
        success: function (data) // Variable data contains the data we get from serverside
        {
            $('<option/>').val("").html("--").appendTo('#vendorid');
            $('<option/>').addClass("").val("").html("--").appendTo('#librarynameid');
            $('<option/>').addClass("").val("").html("--").appendTo('#libraryversionid');
            var vendjs, libjs, verjs;
            for (var i = 0; i < data.vendors.length; i++) {
                vendjs = data.vendors[i];

                $('<option/>').val(vendjs.id).html(vendjs.vendor).appendTo('#vendorid');
                for (var j = 0; j < vendjs.libraries.length; j++) {
                    libjs = vendjs.libraries[j];
                    var id = libjs.libid;
                    $('<option/>').addClass(vendjs.id.toString()).val(libjs.libid).html(libjs.libname).appendTo('#librarynameid');

                    for (var k = 0; k < libjs.versions.length; k++) {
                        verjs = libjs.versions[k];

                        $('<option/>').addClass(libjs.libid.toString()).val(verjs.libverid).html(verjs.libver).appendTo('#libraryversionid');

                    }
                }
            }
            $("#librarynameid").chainedTo("#vendorid");
            $("#libraryversionid").chainedTo("#librarynameid");
        }


    });

});


$(document).on("change",".libraryversionidclass",function() {
    $('input#libraryversion').val($('#libraryversionid option:selected').text());
});

$(document).on("change",".librarynameidclass",function() {
    $('input#libraryname').val($('#librarynameid option:selected').text());
});

$(document).on("change",".vendoridclass",function() {

    $(document.getElementById('vendor')).val($('#vendorid option:selected').text());
});

$(document).on("change",".licenseidsclass",function() {

    $(document.getElementById('license')).val($('#licenseids option:selected').text());
});

$(document).on("change",".languageidclass",function() {

    $(document.getElementById('language')).val($('#languageid option:selected').text());
});

$(document).on("change",".licenselosefocus",function() {

    var values = [];
    $('#licenseids option').each(function() {
        values.push( $(this).attr('value') );
    });
    var name = $(document.getElementById('license')).val();
    var i;
    for (i = 0; i < values.length; i++)
    {
        if(values[i]!= name)
        {
        $(document.getElementById('Licensefile')).show();
        $(document.getElementById('Licensefilelabel')).show();
        }
    }
});

$(document).on("change",".checkvalidity",function() {

    var id = $(this).val();

    var uri = contextPath() + '/usermanagement/validateuser/'+id;

    $.ajax({
        url: uri,
        type: 'GET',
        dataType: "text",
        success: function (data) // Variable data contains the data we get from serverside
        {
            $('#userManagaementContainer').load(window.location.href + ' #userManagaementContainer');
        }
    });

});

$(document).on("click",".deleteUser",function() {
    var id = $(this).data('userid');
    var uri = contextPath() + '/usermanagement/deleteuser/'+id;

    $.ajax({
        url: uri,
        type: 'GET',
        dataType: "text",
        success: function (data) // Variable data contains the data we get from serverside
        {
            $('#userManagaementContainer').load(window.location.href + ' #userManagaementContainer');
        }
    });

});

$(document).on("change",".rolename",function() {

    var id = $(this).data('userid');
    var role = $(this).val();

    var uri = contextPath() + '/usermanagement/changeuserrole/'+id+'/'+role;

    $.ajax({
        url: uri,
        type: 'GET',
        dataType: "text",
        success: function (data) // Variable data contains the data we get from serverside
        {
            $('#userManagaementContainer').load(window.location.href + ' #userManagaementContainer');
        }
    });

});

$(document).on("click", ".trendButton", function () {
    var days = $(this).data("id");
    remove_dashboard_chart();
    vulnerability_trend_query(days);
});

function togglePasswordFields(checkbox) {
    if (checkbox.checked) {
        document.getElementById('password').value='';
        document.getElementById('password').disabled=true;
        document.getElementById('chkpassword').value='';
        document.getElementById('chkpassword').disabled=true;
    } else {
        document.getElementById('password').disabled=false;
        document.getElementById('chkpassword').disabled=false;
    }
}
