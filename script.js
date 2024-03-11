function onWindowLoad() {
    onDataChange();
}

function onDataChange() {
    data = document.getElementById("data");
    content = document.getElementById("content");

    ba = Datas.get(data.value)

    content.value = ba;

    content.scrollLeft = 0;
    content.scrollTop = 0;
}