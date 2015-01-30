/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

var vulnerability_trend_data = {};

var dashboard_chart_options = {
    multiTooltipTemplate: "<%= value %> (<%= datasetLabel %>)"
};

function dashboard_chart() {
    var can = jQuery('#dashboard_chart');
    var container = can.parent().parent(); // get width from proper parent
    var $container = jQuery(container);

    can.attr('width', $container.width()); //max width
    can.attr('height', $container.height()); //max height

    render_dashboard_chart();
}

function render_dashboard_chart() {
    var can = jQuery('#dashboard_chart');
    var ctx = can.get(0).getContext("2d");
    var chart = new Chart(ctx).Line(vulnerability_trend_data, dashboard_chart_options);
}

function remove_dashboard_chart() {
    $('canvas').remove();
    var container = document.getElementById("dashboard_canvas_container");
    var canvas = document.createElement("canvas");
    canvas.id = "dashboard_chart";
    canvas.width = container.offsetWidth;
    canvas.height = 400;
    container.appendChild(canvas);
}

function resize_dashboard_chart() {
    remove_dashboard_chart();
    render_dashboard_chart();
}

function vulnerability_trend_query(days) {
    jQuery.get(contextPath() + "/vulnerabilityTrend/" + days,
        function (data) {
            vulnerability_trend_data = {
                labels: data.mapProperty('date'),
                datasets: [
                    {
                        label: "High",
                        fillColor: "rgba(255,51,51,0.2)",
                        strokeColor: "rgba(255,51,51,1)",
                        pointColor: "rgba(255,51,51,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(255,51,51,1)",
                        data: data.mapProperty('high')
                    },
                    {
                        label: "Medium",
                        fillColor: "rgba(255,204,51,0.2)",
                        strokeColor: "rgba(255,204,51,1)",
                        pointColor: "rgba(255,204,51,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(255,204,51,1)",
                        data: data.mapProperty('medium')
                    },
                    {
                        label: "Low",
                        fillColor: "rgba(51,153,255,0.2)",
                        strokeColor: "rgba(51,153,255,1)",
                        pointColor: "rgba(51,153,255,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(51,153,255,1)",
                        data: data.mapProperty('low')
                    },
                    {
                        label: "Total",
                        fillColor: "rgba(220,220,220,0.2)",
                        strokeColor: "rgba(220,220,220,1)",
                        pointColor: "rgba(220,220,220,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(220,220,220,1)",
                        data: data.mapProperty('total')
                    }
                ]
            };
            dashboard_chart();
        }
    );
}

jQuery(document).ready(function($) {
    jQuery(window).resize(resize_dashboard_chart);
    $("#trendYearButton").button('toggle');
    vulnerability_trend_query(365);
});

Array.prototype.mapProperty = function(property) {
    return this.map(function (obj) {
        return obj[property];
    });
};

