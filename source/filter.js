'use strict';

//ВАРИАНТ 15
//Задание: Напишите функцию filter, которая фильтрует html-код, оставляя только разрешённые html-теги
//Задачу решил Уймин М.С.

function filter (html) {
	const regexp = /<\/?\w+(\s*\w+=(\w+|"[^"]*")\s*)*>/g;//Регулярка, выбирающая тэги
	const ValueType = Object.freeze({ text: 1,
					  openingTag: 2,
					  closingTag: 3 });//Возможные типы нод в html
	let parsed = [];
	let cursor = 0;
	let tag = regexp.exec(html);
	while (tag !== null) {
		if (tag.index !== cursor) {
			//Между предыдущей нодой и новым тэгом есть текст
			parsed.push({ type: ValueType.text,
				      value: html.substring(cursor, tag.index) });
		}
		if (tag[0].charAt(1) === '/') {
			//По регулярке нашли закрывающий тэг
			parsed.push({ type: ValueType.closingTag,
				      value: tag[0],
				      name: tag[0].match(/<\/\w+/)[0].slice(2,-1)});
			for (let i=parsed.length-1; i>=0; i--) {
				if (parsed[i].type === ValueType.openingTag &&
				    parsed[i].name === parsed[parsed.length-1].name &&
				    parsed[i].closed === null) {
					//Полагая, что тэги расположены в корректном порядке,
					//закрываем последний открытый тэг
					parsed[i].closed = parsed.length - 1;
					break;
				}
			}
		} else {
			//По регулярке нашли открывающий тэг
			parsed.push({ type: ValueType.openingTag,
				      value: tag[0],
				      name: tag[0].match(/<\w+/)[0].slice(1,-1),
				      closed: null });
		}
		cursor = tag.index + tag[0].length;
		tag = regexp.exec(html);
	}
	if (cursor < html.length) {
		//Обрабатываем текст после последнего тэга
		parsed.push({ type: ValueType.text,
			      value: html.substring(cursor) });
	}

	return parsed.reduce((str, item) => {
		if (item.type === ValueType.text) {
			return str + esc(item.value);
		} else {
			if (item.type === ValueType.openingTag && isXSS(item.value)) {
				//Экранируем пару XSS тэгов
				item.value = esc(item.value);
				if (item.closed !== null) {
					parsed[item.closed].value = esc(parsed[item.closed].value);
				}
			}
			return str + item.value;
		}
	}, '');
}

function esc (str) {
	const htmlEscapes = {
        	'&': '&amp;',
        	'<': '&lt;',
        	'>': '&gt;',
        	'"': '&quot;',
        	"'": '&#39;'
    	};
   	return str.replace(/[&<>"']/g, match => {
		//Экранируем все символы в тексте
		return htmlEscapes[match];
	});
}

function isXSS (tag) {
	let tagName = tag.match(/<\w+/)[0].slice(1);
	const xssTags = ['script'];
	if (xssTags.includes(tagName)) {
		return true;
	}
	let attrs = tag.match(/\w+=/g);
	if (attrs === null) {
		//В теге нет атрибутов
		return false;
	}
	attrs = attrs.map(elem => {
		return elem.slice(0,-1);
	});
	const xssAttrs = ['value', 'href', 'src', 'style', 'onblur', 'onchange', 'onclick', 'ondbclick',
		'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown','onmousemove', 'onmouseout',
			'onmouseover', 'onmouseup', 'onreset', 'onselect', 'onsubmit'];
	return attrs.some(item => {
		return xssAttrs.includes(item);
	});
}