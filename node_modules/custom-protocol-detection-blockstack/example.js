$(function () {
    $("div[href]").click(function (event) {
        window.protocolCheck($(this).attr("href"),
            function () {
                alert("protocol not recognized");
            });
        event.preventDefault ? event.preventDefault() : event.returnValue = false;
    });
});
