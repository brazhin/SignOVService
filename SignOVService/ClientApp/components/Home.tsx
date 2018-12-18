import * as React from 'react';
import { RouteComponentProps } from 'react-router-dom';

export default class Home extends React.Component<RouteComponentProps<{}>, {}> {
	constructor() {
		super();

	}

	public render() {
		return <h1>Проект Сервиса подписания</h1>;
	}
}