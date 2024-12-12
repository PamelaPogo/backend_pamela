import {Producto} from "../../producto/entities/producto.entity";
import {Column ,Entity, OneToOne, PrimaryGeneratedColumn} from "typeorm";

@Entity()
export class Categoria {
    @PrimaryGeneratedColumn()
    id:number;
    @Column()
    nombre:string;

    @Column()
    detalle:string;

    @OneToOne(()=>Producto,(prod)=>prod.categoria)
    producto:Producto[]
}
