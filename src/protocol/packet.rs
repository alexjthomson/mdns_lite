use super::{
    MdnsFlags,
    MdnsHeader,
    Query,
    Response,
    Opcode,
    ParseMdnsError,
};

/// Represents an mDNS packet.
#[derive(PartialEq, Debug)]
pub struct MdnsPacket {
    /// Header for the [`MdnsPacket`].
    header: MdnsHeader,
    /// The questions section of the [`MdnsPacket`].
    question_records: Vec<Query>,
    /// The answers section of the [`MdnsPacket`].
    answer_records: Vec<Response>,
    /// The authorities section of the [`MdnsPacket`].
    authority_records: Vec<Response>,
    /// The additional records section of the [`MdnsPacket`].
    additional_records: Vec<Response>,
}

impl MdnsPacket {
    /// Creates a new [`MdnsPacket`].
    /// 
    /// This allows full control over the [`MdnsPacket`] creation.
    /// 
    /// For a simpler API, prefer using either [`MdnsPacket::new_query`] or
    /// [`MdnsPacket::new_response`].
    #[inline]
    #[must_use]
    pub fn new(
        header: MdnsHeader,
        questions: Vec<Query>,
        answers: Vec<Response>,
        authorities: Vec<Response>,
        additionals: Vec<Response>,
    ) -> Self {
        Self {
            header,
            question_records: questions,
            answer_records: answers,
            authority_records: authorities,
            additional_records: additionals,
        }
    }

    /// Creates a new empty [`MdnsPacket`] with blank [`MdnsFlags`] and no
    /// records.
    #[inline]
    #[must_use]
    pub fn new_empty(
        transaction_id: u16,
    ) -> Self {
        Self {
            header: MdnsHeader::new_empty(transaction_id),
            question_records: Vec::new(),
            answer_records: Vec::new(),
            authority_records: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Creates a new query [`MdnsPacket`] containing the given records.
    /// 
    /// This automatically derives the header flags for the query.
    #[must_use]
    pub fn new_with_records(
        transaction_id: u16,
        questions: Vec<Query>,
        answers: Vec<Response>,
        authorities: Vec<Response>,
        additionals: Vec<Response>,
    ) -> Self {
        let mut flags = MdnsFlags::empty();
        flags.set_opcode(Opcode::Query);
        flags.set_qr(!answers.is_empty());
        flags.set_aa(!authorities.is_empty());
        let header = MdnsHeader::new(
            transaction_id,
            flags,
            questions.len() as u16,
            answers.len() as u16,
            authorities.len() as u16,
            additionals.len() as u16,
        );
        Self {
            header,
            question_records: questions,
            answer_records: answers,
            authority_records: authorities,
            additional_records: additionals,
        }
    }

    /// Creates a new query [`MdnsPacket`] containing the given questions.
    /// 
    /// This automatically derives the header flags for the query.
    #[must_use]
    pub fn new_query(
        transaction_id: u16,
        questions: Vec<Query>
    ) -> Self {
        // Create the header:
        let mut flags = MdnsFlags::empty();
        flags.set_opcode(Opcode::Query);
        flags.set_qr(false);
        let total_questions = questions.len() as u16;
        let header = MdnsHeader::new(
            transaction_id,
            flags,
            total_questions,
            0,
            0,
            0,
        );
        // Create the packet:
        Self {
            header,
            question_records: questions,
            answer_records: Vec::new(),
            authority_records: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Creates a new response [`MdnsPacket`] containing the given answers,
    /// authorities, and additionals.
    /// 
    /// This automatically derives the header flags for a response.
    #[must_use]
    pub fn new_response(
        transaction_id: u16,
        answers: Vec<Response>,
        authorities: Vec<Response>,
        additionals: Vec<Response>,
    ) -> Self {
        // Create header:
        let mut flags = MdnsFlags::empty();
        flags.set_opcode(Opcode::Query);
        flags.set_qr(true);
        let total_answers = answers.len() as u16;
        let total_authority_records = authorities.len() as u16;
        let total_additional_records = additionals.len() as u16;
        let header = MdnsHeader::new(
            transaction_id,
            flags,
            0,
            total_answers,
            total_authority_records,
            total_additional_records,
        );
        // Create the packet:
        Self {
            header,
            question_records: Vec::new(),
            answer_records: answers,
            authority_records: authorities,
            additional_records: additionals,
        }
    }

    /// Returns the transaction ID of the [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn transaction_id(&self) -> u16 {
        self.header.id()
    }

    /// Returns an immutable reference to the header of the [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn header(&self) -> &MdnsHeader {
        &self.header
    }

    /// Returns an immutable reference to the questions within the
    /// [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn questions(&self) -> &Vec<Query> {
        &self.question_records
    }

    /// Returns `true` if the [`MdnsPacket`] contains any questions.
    #[inline]
    #[must_use]
    pub fn has_questions(&self) -> bool {
        !self.question_records.is_empty()
    }

    /// Returns an immutable reference to the answers within the [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn answers(&self) -> &Vec<Response> {
        &self.answer_records
    }

    /// Returns `true` if the [`MdnsPacket`] contains any answers.
    #[inline]
    #[must_use]
    pub fn has_answers(&self) -> bool {
        !self.answer_records.is_empty()
    }

    /// Returns an immutable reference to the authorities within the
    /// [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn authorities(&self) -> &Vec<Response> {
        &self.authority_records
    }

    /// Returns `true` if the [`MdnsPacket`] contains any authority records.
    #[inline]
    #[must_use]
    pub fn has_authorities(&self) -> bool {
        !self.authority_records.is_empty()
    }

    /// Returns an immutable reference to the additional records within the
    /// [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn additionals(&self) -> &Vec<Response> {
        &self.additional_records
    }

    /// Returns `true` if the [`MdnsPacket`] contains any additional records.
    #[inline]
    #[must_use]
    pub fn has_additionals(&self) -> bool {
        !self.additional_records.is_empty()
    }

    /// Adds a new question to the [`MdnsPacket`] and updates the header.
    pub fn add_question(&mut self, question: Query) {
        self.question_records.push(question);
        self.header.set_total_question_records(self.question_records.len() as u16);
    }

    /// Adds a set of questions to the [`MdnsPacket`] and updates the header.
    pub fn add_questions(&mut self, questions: Vec<Query>) {
        self.question_records.extend(questions);
        self.header.set_total_question_records(self.question_records.len() as u16);
    }

    /// Adds a new answer to the [`MdnsPacket`] and updates the header.
    pub fn add_answer(&mut self, answer: Response) {
        self.answer_records.push(answer);
        self.header.set_total_answer_records(self.answer_records.len() as u16);
    }

    /// Adds a set of answers to the [`MdnsPacket`] and updates the header.
    pub fn add_answers(&mut self, answers: Vec<Response>) {
        self.answer_records.extend(answers);
        self.header.set_total_answer_records(self.answer_records.len() as u16);
    }

    /// Adds a new authority to the [`MdnsPacket`] and updates the header.
    pub fn add_authority(&mut self, authority: Response) {
        self.authority_records.push(authority);
        self.header.set_total_authority_records(self.authority_records.len() as u16);
    }

    /// Adds new authorities to the [`MdnsPacket`] and updates the header.
    pub fn add_authorities(&mut self, authorities: Vec<Response>) {
        self.authority_records.extend(authorities);
        self.header.set_total_authority_records(self.authority_records.len() as u16);
    }

    /// Adds a new additional record to the [`MdnsPacket`] and updates the
    /// header.
    pub fn add_additional(&mut self, additional: Response) {
        self.additional_records.push(additional);
        self.header.set_total_additional_records(self.additional_records.len() as u16);
    }

    /// Adds a set of additional records to the [`MdnsPacket`] and updates the
    /// header.
    pub fn add_additionals(&mut self, additionals: Vec<Response>) {
        self.additional_records.extend(additionals);
        self.header.set_total_additional_records(self.additional_records.len() as u16);
    }

    /// Converts the [`MdnsPacket`] into raw bytes that can be sent as a packet.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = self.header.to_bytes().to_vec();
        fn write_queries(packet: &mut Vec<u8>, queries: &[Query]) {
            for query in queries.iter() {
                query.to_bytes_extend(packet);
            }
        }
        fn write_responses(packet: &mut Vec<u8>, responses: &[Response]) {
            for response in responses.iter() {
                response.to_bytes_extend(packet);
            }
        }
        write_queries(&mut packet, &self.question_records);
        write_responses(&mut packet, &self.answer_records);
        write_responses(&mut packet, &self.authority_records);
        write_responses(&mut packet, &self.additional_records);
        packet
    }

    /// Converts raw mDNS packet bytes into an [`MdnsPacket`].
    pub fn from_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, ParseMdnsError> {
        let mut i: usize = *offset;

        // The first thing we need to read from the mDNS packet is the header:
        let header = MdnsHeader::from_bytes(bytes, &mut i)?;

        fn read_queries(
            bytes: &[u8],
            offset: &mut usize,
            total_queries: u16,
        ) -> Result<Vec<Query>, ParseMdnsError> {
            let mut queries = Vec::with_capacity(total_queries as usize);
            for _ in 0..total_queries {
                queries.push(Query::from_bytes(bytes, offset)?);
            }
            Ok(queries)
        }

        fn read_responses(
            bytes: &[u8],
            offset: &mut usize,
            total_responses: u16,
        ) -> Result<Vec<Response>, ParseMdnsError> {
            let mut responses = Vec::with_capacity(total_responses as usize);
            for _ in 0..total_responses {
                responses.push(Response::from_bytes(bytes, offset)?);
            }
            Ok(responses)
        }

        // Now that we have the header, we know the number of question, answer,
        // authority, and addition records that the packet contains. We can now
        // read them:
        let question_records = read_queries(
            bytes,
            &mut i,
            header.total_question_records(),
        )?;
        let answer_records = read_responses(
            bytes,
            &mut i,
            header.total_answer_records(),
        )?;
        let authority_records = read_responses(
            bytes,
            &mut i,
            header.total_authority_records(),
        )?;
        let additional_records = read_responses(
            bytes,
            &mut i,
            header.total_additional_records(),
        )?;
        
        // We can now construct the mDNS packet:
        *offset = i;
        Ok(Self {
            header,
            question_records,
            answer_records,
            authority_records,
            additional_records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_new_empty_packet() {
        let packet = MdnsPacket::new_empty(1234);
        assert_eq!(packet.transaction_id(), 1234);
        assert_eq!(packet.questions().len(), 0);
        assert_eq!(packet.answers().len(), 0);
        assert_eq!(packet.authorities().len(), 0);
        assert_eq!(packet.additionals().len(), 0);
    }

    #[test]
    fn test_populate_packet() {
        let mut packet = MdnsPacket::new_empty(1234);
        let question: Query = Query::new(
            DnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            DnsType::A,
            DnsClass::IN,
        );

        packet.add_question(question.clone());
        assert_eq!(packet.questions().len(), 1);
        assert_eq!(packet.questions()[0], question);

        let response = Response::new(
            DnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            DnsType::A,
            DnsClass::IN,
            120,
            vec![127, 0, 0, 1],
        );

        packet.add_answer(response.clone());
        assert_eq!(packet.answers().len(), 1);
        assert_eq!(packet.answers()[0], response);

        packet.add_authority(response.clone());
        assert_eq!(packet.authorities().len(), 1);
        assert_eq!(packet.authorities()[0], response);

        packet.add_additional(response.clone());
        assert_eq!(packet.additionals().len(), 1);
        assert_eq!(packet.additionals()[0], response);
    }

    #[test]
    fn test_empty_packet_to_bytes() {
        let packet = MdnsPacket::new_empty(1234);
        assert_eq!(packet.to_bytes(), vec![
            0x04, 0xd2, // ID
            0x00, 0x00, // Flags
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]);
    }

    #[test]
    fn test_packet_from_bytes() {
        fn test_from_bytes(packet: MdnsPacket) {
            let from_bytes = MdnsPacket::from_bytes(
                &packet.to_bytes(),
                &mut 0,
            ).expect("Failed to convert raw packet bytes into a new packet");
            assert_eq!(from_bytes, packet);
        }
        // Test query packet:
        test_from_bytes(MdnsPacket::new_query(1234, vec![
            Query::new(
                DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                DnsType::PTR,
                DnsClass::IN,
            ),
        ]));
        // Test response packet:
        test_from_bytes(
            MdnsPacket::new_response(
                1234,
                vec![
                        Response::new(
                        DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                        DnsType::PTR,
                        DnsClass::IN,
                        120,
                        vec![127, 0, 0, 1],
                    )
                ],
                vec![
                        Response::new(
                        DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                        DnsType::PTR,
                        DnsClass::IN,
                        300,
                        Vec::new(),
                    )
                ],
                vec![
                        Response::new(
                        DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                        DnsType::PTR,
                        DnsClass::IN,
                        600,
                        vec![0, 1, 2, 3, 4, 5, 6, 7],
                    )
                ],
            )
        );
    }
}